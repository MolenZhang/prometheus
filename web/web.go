// Copyright 2013 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"bytes"
	"encoding/json"
	//	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
	pprof_runtime "runtime/pprof"
	template_text "text/template"

	"github.com/opentracing-contrib/go-stdlib/nethttp"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/route"
	"golang.org/x/net/context"
	"golang.org/x/net/netutil"

	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/notifier"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/retrieval"
	"github.com/prometheus/prometheus/rules"
	"github.com/prometheus/prometheus/storage/local"
	"github.com/prometheus/prometheus/template"
	"github.com/prometheus/prometheus/util/httputil"
	api_v1 "github.com/prometheus/prometheus/web/api/v1"
	"github.com/prometheus/prometheus/web/ui"
)

var localhostRepresentations = []string{"127.0.0.1", "localhost"}

//保存上线的配置文件信息
var (
	CFile      string
	MsgSendBtn bool
)

// Handler serves various HTTP endpoints of the Prometheus server
type Handler struct {
	targetManager *retrieval.TargetManager
	ruleManager   *rules.Manager
	queryEngine   *promql.Engine
	context       context.Context
	storage       local.Storage
	notifier      *notifier.Notifier

	apiV1 *api_v1.API

	router       *route.Router
	listenErrCh  chan error
	quitCh       chan struct{}
	reloadCh     chan chan error
	options      *Options
	configString string
	versionInfo  *PrometheusVersion
	birth        time.Time
	cwd          string
	flagsMap     map[string]string

	externalLabels model.LabelSet
	mtx            sync.RWMutex
	now            func() model.Time
}

// ApplyConfig updates the status state as the new config requires.
func (h *Handler) ApplyConfig(conf *config.Config) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	h.externalLabels = conf.GlobalConfig.ExternalLabels
	h.configString = conf.String()

	return nil
}

// PrometheusVersion contains build information about Prometheus.
type PrometheusVersion struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Branch    string `json:"branch"`
	BuildUser string `json:"buildUser"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
}

// Options for the web Handler.
type Options struct {
	Context       context.Context
	Storage       local.Storage
	QueryEngine   *promql.Engine
	TargetManager *retrieval.TargetManager
	RuleManager   *rules.Manager
	Notifier      *notifier.Notifier
	Version       *PrometheusVersion
	Flags         map[string]string

	ListenAddress        string
	ReadTimeout          time.Duration
	MaxConnections       int
	ExternalURL          *url.URL
	RoutePrefix          string
	MetricsPath          string
	UseLocalAssets       bool
	UserAssetsPath       string
	ConsoleTemplatesPath string
	ConsoleLibrariesPath string
	EnableQuit           bool
}

// New initializes a new web Handler.
func New(o *Options) *Handler {
	router := route.New()
	cwd, err := os.Getwd()

	if err != nil {
		cwd = "<error retrieving current working directory>"
	}

	h := &Handler{
		router:      router,
		listenErrCh: make(chan error),
		quitCh:      make(chan struct{}),
		reloadCh:    make(chan chan error),
		options:     o,
		versionInfo: o.Version,
		birth:       time.Now(),
		cwd:         cwd,
		flagsMap:    o.Flags,

		context:       o.Context,
		targetManager: o.TargetManager,
		ruleManager:   o.RuleManager,
		queryEngine:   o.QueryEngine,
		storage:       o.Storage,
		notifier:      o.Notifier,

		apiV1: api_v1.NewAPI(o.QueryEngine, o.Storage, o.TargetManager, o.Notifier),
		now:   model.Now,
	}

	if o.RoutePrefix != "/" {
		// If the prefix is missing for the root path, prepend it.
		router.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, o.RoutePrefix, http.StatusFound)
		})
		router = router.WithPrefix(o.RoutePrefix)
	}

	instrh := prometheus.InstrumentHandler
	instrf := prometheus.InstrumentHandlerFunc

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, path.Join(o.ExternalURL.Path, "/graph"), http.StatusFound)
	})

	router.Get("/alerts", instrf("alerts", h.alerts))
	router.Get("/graph", instrf("graph", h.graph))
	router.Get("/status", instrf("status", h.status))
	router.Get("/flags", instrf("flags", h.flags))
	router.Get("/config", instrf("config", h.config))
	router.Get("/rules", instrf("rules", h.rules))
	router.Get("/targets", instrf("targets", h.targets))
	router.Get("/version", instrf("version", h.version))

	router.Get("/heap", instrf("heap", dumpHeap))

	router.Get(o.MetricsPath, prometheus.Handler().ServeHTTP)

	router.Get("/federate", instrh("federate", httputil.CompressionHandler{
		Handler: http.HandlerFunc(h.federation),
	}))

	//BCM 界面监控 服务状态信息
	router.Post("/promforbcm", h.creAlertForBCM)

	router.Put("/promforbcm", h.updAlertForBCM)

	router.Del("/promforbcm", h.delAlertForBCM)

	//BCM 界面监控 集群节点信息
	router.Post("/k8sclusterinfo", h.creNodesInfo)

	router.Put("/k8sclusterinfo", h.updNodesInfo)

	router.Del("/k8sclusterinfo", h.delNodesInfo)

	//BCM 界面增加 外部export监控对象
	router.Post("/extern", h.addExternExporter)

	h.apiV1.Register(router.WithPrefix("/api/v1"))

	router.Get("/consoles/*filepath", instrf("consoles", h.consoles))

	router.Get("/static/*filepath", instrf("static", serveStaticAsset))

	if o.UserAssetsPath != "" {
		router.Get("/user/*filepath", instrf("user", route.FileServe(o.UserAssetsPath)))
	}

	if o.EnableQuit {
		router.Post("/-/quit", h.quit)
	}

	router.Post("/-/reload", h.reload)
	router.Get("/-/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "This endpoint requires a POST request.\n")
	})

	router.Get("/debug/*subpath", http.DefaultServeMux.ServeHTTP)
	router.Post("/debug/*subpath", http.DefaultServeMux.ServeHTTP)

	return h
}

func serveStaticAsset(w http.ResponseWriter, req *http.Request) {
	fp := route.Param(req.Context(), "filepath")
	fp = filepath.Join("web/ui/static", fp)

	info, err := ui.AssetInfo(fp)
	if err != nil {
		log.With("file", fp).Warn("Could not get file info: ", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	file, err := ui.Asset(fp)
	if err != nil {
		if err != io.EOF {
			log.With("file", fp).Warn("Could not get file: ", err)
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}

	http.ServeContent(w, req, info.Name(), info.ModTime(), bytes.NewReader(file))
}

// ListenError returns the receive-only channel that signals errors while starting the web server.
func (h *Handler) ListenError() <-chan error {
	return h.listenErrCh
}

// Quit returns the receive-only quit channel.
func (h *Handler) Quit() <-chan struct{} {
	return h.quitCh
}

// Reload returns the receive-only channel that signals configuration reload requests.
func (h *Handler) Reload() <-chan chan error {
	return h.reloadCh
}

// Run serves the HTTP endpoints.
func (h *Handler) Run() {
	log.Infof("Listening on %s", h.options.ListenAddress)
	operationName := nethttp.OperationNameFunc(func(r *http.Request) string {
		return fmt.Sprintf("%s %s", r.Method, r.URL.Path)
	})
	server := &http.Server{
		Addr:        h.options.ListenAddress,
		Handler:     nethttp.Middleware(opentracing.GlobalTracer(), h.router, operationName),
		ErrorLog:    log.NewErrorLogger(),
		ReadTimeout: h.options.ReadTimeout,
	}
	listener, err := net.Listen("tcp", h.options.ListenAddress)
	if err != nil {
		h.listenErrCh <- err
	} else {
		limitedListener := netutil.LimitListener(listener, h.options.MaxConnections)
		h.listenErrCh <- server.Serve(limitedListener)
	}
}

func (h *Handler) alerts(w http.ResponseWriter, r *http.Request) {
	alerts := h.ruleManager.AlertingRules()
	alertsSorter := byAlertStateAndNameSorter{alerts: alerts}
	sort.Sort(alertsSorter)

	alertStatus := AlertStatus{
		AlertingRules: alertsSorter.alerts,
		AlertStateToRowClass: map[rules.AlertState]string{
			rules.StateInactive: "success",
			rules.StatePending:  "warning",
			rules.StateFiring:   "danger",
		},
	}
	h.executeTemplate(w, "alerts.html", alertStatus)
}

func (h *Handler) consoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := route.Param(ctx, "filepath")

	file, err := http.Dir(h.options.ConsoleTemplatesPath).Open(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	text, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Provide URL parameters as a map for easy use. Advanced users may have need for
	// parameters beyond the first, so provide RawParams.
	rawParams, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	params := map[string]string{}
	for k, v := range rawParams {
		params[k] = v[0]
	}
	data := struct {
		RawParams url.Values
		Params    map[string]string
		Path      string
	}{
		RawParams: rawParams,
		Params:    params,
		Path:      strings.TrimLeft(name, "/"),
	}

	tmpl := template.NewTemplateExpander(h.context, string(text), "__console_"+name, data, h.now(), h.queryEngine, h.options.ExternalURL)
	filenames, err := filepath.Glob(h.options.ConsoleLibrariesPath + "/*.lib")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result, err := tmpl.ExpandHTML(filenames)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, result)
}

func (h *Handler) graph(w http.ResponseWriter, r *http.Request) {
	h.executeTemplate(w, "graph.html", nil)
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	h.executeTemplate(w, "status.html", struct {
		Birth         time.Time
		CWD           string
		Version       *PrometheusVersion
		Alertmanagers []*url.URL
	}{
		Birth:         h.birth,
		CWD:           h.cwd,
		Version:       h.versionInfo,
		Alertmanagers: h.notifier.Alertmanagers(),
	})
}

func (h *Handler) flags(w http.ResponseWriter, r *http.Request) {
	h.executeTemplate(w, "flags.html", h.flagsMap)
}

//Molen:报警规则配置结构定义
type alertRulesFile struct {
	AlertName    string      `json:"alert_name"`             //报警名称
	Namespace    string      `json:"namespace"`              //租户
	Service      string      `json:"service"`                //服务
	AlertTargets string      `json:"alert_targets"`          //svc_status/svc_resource/svc_network/nodes/
	AlertMetrics string      `json:"alert_metrics"`          //监控指标
	Threshold    string      `json:"threshold"`              //阈值
	Duration     string      `json:"duration"`               //对象达到阈值持续时间
	AlertLevel   string      `json:"alert_level"`            //报警级别 warning 或者 critical
	AlertType    AlertInfo   `json:"alert_type"`             //报警方式 支持短信 邮件
	RedisTarget  []RedisInfo `json:"redis_target,omitempty"` //redis 相关数据
}

type AlertInfo struct {
	MsgReceiver string `json:"msg_receiver"` //收件人
	MsgAddr     string `json:"msg_addr"`     //收件人联系方式 邮箱地址或者手机号
}
type RedisInfo struct {
	TargetName string `json:"target_name"` //指标抓取名称
	RedisAddr  string `json:"redis_addr"`  //redis 地址
	RedisPort  string `json:"redis_port"`  //redis 端口
}

func (h *Handler) reloadpromcfg(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	log.Infoln("界面开始重置prometheus 配置文件！！！！")

	pCfg := alertRulesFile{}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Infoln("Molen_failed to receive the data from web:", err)
	}
	json.Unmarshal(data, &pCfg)

	if len(pCfg.RedisTarget) != 0 {
		redisTargetCfg(&pCfg)
	}
	//if pCfg.AlertName

}
func redisTargetCfg(pCfg *alertRulesFile) {
	f, err := os.OpenFile("/etc/prometheus.yaml", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		log.Errorf("failed to open promethesCfg file with err:", err)
	}
	for k, _ := range pCfg.RedisTarget {
		cfgContentAppend := fmt.Sprintf(`- job_name: %s
  static_configs:
  - targets: [%s]`, pCfg.RedisTarget[k].TargetName,
			pCfg.RedisTarget[k].RedisAddr+":"+pCfg.RedisTarget[k].RedisPort)

		f.WriteString("\n")
		f.WriteString(cfgContentAppend)
	}

}

const (
	cpu       string = "cpu"       //CPU
	memory    string = "memory"    //内存
	svcStatus string = "svcStatus" //服务状态

	nodeCPU    string = "nodeCPU"    //集群节点CPU
	nodeDisk   string = "nodeDisk"   //集群节点磁盘空间
	nodeMemory string = "nodeMemory" //集群节点内存

	message    string = "message" //短信
	k8sCluster string = "k8sCluster"
	reload     string = "/-/reload"

	alertRules           string = "alert.rules"          //规则文件
	preLocation          string = "/etc/palert/"         //保存prometheus规则文件的路径
	prometheusCfg        string = "/etc/prometheus.yaml" //prometheus服务配置文件
	clusterAlertReceiver string = "clusterAlertRec"      //集群报警信息接收者
)

type respMsg struct {
	Status int    `json:"status"` //200_succ;400_failed
	Msg    string `json:"Msg"`    //msg
}

var svcReceiverMap = make(map[string]string, 0)

func addSvcReceiverToMap(svc, receiver string) {

	svcReceiverMap[svc] = receiver
}

func delSvcReceiverFromMap(key string) {
	delete(svcReceiverMap, key)
}

func getSvcReceiverMap(key string) string {
	return svcReceiverMap[key]
}

func updSvcReceiverMap(key string, v string) {
	svcReceiverMap[key] = v
}

func getAllMapSvcRecInfo() map[string]string {
	return svcReceiverMap
}

func (h *Handler) creAlertForBCM(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	log.Infoln("BCM 启动监控对象配置....")

	var alertTargets = struct {
		AlertJob      []string          `json:"alertJob"`      //监控对象
		AlertSendType map[string]string `json:"alertSendType"` //报警发送方式
		Namespace     string            `json:"namespace"`     //租户
		SvcName       string            `json:"svcName"`       //服务
		Receiver      string            `json:"receiver"`      //接收者
		//AlertDurationTime string            `json:"alertDurationTime"`         //报警触发持续时间
		CPUThreshold    string `json:"cpuThreshold,omitempty"`    //CPU配置
		MemoryThreshold string `json:"memoryThreshold,omitempty"` //Memory配置
	}{}

	var resp respMsg

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorln("解析BCM界面传参出错", err)
		resp.respFail(w, "界面参数配置出错")
	}
	json.Unmarshal(data, &alertTargets)

	log.Infoln("解析BCM传来的数据为:", alertTargets)

	if false == MsgSendBtn {
		for sendType, _ := range alertTargets.AlertSendType {
			if sendType == message {
				resp.respFail(w, "该环境不支持短信发送告警")
				return
			}
		}
	}

	//保存租户和服务的对应关系
	addSvcReceiverToMap(alertTargets.SvcName, alertTargets.Receiver)

	//获取所有map
	log.Infoln("新增时,Map中所存储的数据信息:", getAllMapSvcRecInfo())

	for _, target := range alertTargets.AlertJob {
		switch target {
		case cpu:
			if result := writeCPUCfgToFile(alertTargets.Namespace, alertTargets.SvcName,
				alertTargets.Receiver, alertTargets.CPUThreshold); result != "" {
				resp.respFail(w, result)
				return
			}
		case memory:
			if result := writeMemoryCfgToFile(alertTargets.Namespace, alertTargets.SvcName,
				alertTargets.Receiver, alertTargets.MemoryThreshold); result != "" {
				resp.respFail(w, result)
				return
			}
		default:
			if result := writeSvcStatusToFile(alertTargets.Namespace, alertTargets.SvcName,
				alertTargets.Receiver); result != "" {
				resp.respFail(w, result)
				return
			}
		}
	}
	//重启prometheus 使配置生效
	PromReloadChan <- "reload the proCfg!"

	//与 alertmanager 通信
	sendMsgToAlert(alertTargets.AlertSendType, alertTargets.Receiver, alertTargets.SvcName)
	resp.respSucc(w, "操作成功")
	return
}

func (r *respMsg) respSucc(w http.ResponseWriter, msg string) {
	r.Status = 200
	r.Msg = msg
	result, _ := json.Marshal(r)
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (r *respMsg) respFail(w http.ResponseWriter, msg string) {
	r.Status = 400
	r.Msg = msg
	result, _ := json.Marshal(r)
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)

}

type recLabel struct {
	Match    map[string]string `json:"match"`
	Receiver string            `json:"receiver"`
}

type respInfo struct {
	Status int    `json:"status"`
	ErrMsg string `json:ErrMsg`
}

// 与alertmanager通信
func sendMsgToAlert(alertType map[string]string, receiver, preLabel string) {

	if strings.Contains(preLabel, "-") {
		preLabel = strings.Replace(preLabel, "-", "_", -1)
	}

	var (
		req  Request
		resp respInfo

		recInfo struct {
			LabelInfo recLabel          `json:"labelInfo"`
			AlertType map[string]string `json:"alertType"`
		}
	)

	recInfo.AlertType = make(map[string]string, 0)
	recInfo.LabelInfo.Match = make(map[string]string, 0)

	recInfo.AlertType = alertType
	recInfo.LabelInfo = recLabel{
		Match: map[string]string{
			preLabel + "_" + "receiver": receiver,
		},
		Receiver: preLabel + "_" + receiver,
	}

	req = Request{
		URL:     getInitCfg().AlertManagerURL + reload,
		Content: recInfo,
		Type:    "POST",
	}

	log.Infoln("与alertmanager通信的内容是：", req.Content)
	log.Infoln("与alertmanager通信的URL：", req.URL)

	data, err := req.SendRequestByJSON()
	if err != nil {
		log.Errorln("通信失败：", err)
		return
	}
	json.Unmarshal(data, &resp)
	//返回200表示成功 400错误
	log.Infoln("alertmanager 返回的通信结果是:", resp)
}

//创建规则文件所在路径
func createDir(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) == true {
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				log.Errorln("创建路径出错", err)
				return err
			}
		}
	}
	return nil
}

//判断规则文件中 所查规则 是否存在
func isRuleFilesExist(ruleFileChecked string, ruleFiles []string) bool {
	for _, ruleFile := range ruleFiles {
		if ruleFile == ruleFileChecked {
			return true
		}
	}
	return false
}

//在 配置中增加相应规则
func addRuleFiles(fileName string) string {
	//修改prometheus的配置中关于规则文件的参数
	currentCfg, _ := config.LoadFile(CFile)
	log.Infoln("**********程序中现有的规则文件:***********", currentCfg)
	if false == isRuleFilesExist(fileName, currentCfg.RuleFiles) {
		currentCfg.RuleFiles = append(currentCfg.RuleFiles, fileName)
		f, err := os.OpenFile(prometheusCfg, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			log.Errorln("打开文件出错", err)
			return "规则文件打开失败"
		}

		defer f.Close()
		out, _ := yaml.Marshal(&currentCfg)
		f.Write(out)
	}
	return ""
}

// 关于CPU的报警规则文件
func writeCPUCfgToFile(ns, svc, receiver, threshold string) string {
	rulesDir := preLocation + ns + "/"
	rulesFileName := svc + "_" + cpu + "_" + alertRules

	//如果路径不存在 则创建
	if err := createDir(rulesDir); err != nil {
		return "CPU规则路径创建失败"
	}

	//以服务为单位 增加CPU规则文件
	if errMsg := addRuleFiles(rulesDir + rulesFileName); errMsg != "" {
		return errMsg
	}

	f, err := os.OpenFile(rulesDir+rulesFileName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln("CPU 规则文件写入出错:", err)
		return "CPU报警规则写入出错"
	}
	defer f.Close()

	//规则文件不支持标识符"-"
	log.Infoln("替换前的租户和服务信息是：", ns, svc)
	repNs, repSvc := strReplace(ns, svc)
	log.Infoln("替换后的租户和服务信息是：", repNs, repSvc)

	rulesContent := fmt.Sprintf(`ALERT %s_%s_CPUUsageHigh
  IF sum(rate(container_cpu_usage_seconds_total { namespace =~ "%s.*",pod_name =~ "%s.*",container_name = "%s"}[5m])) / count(node_cpu{mode="system"}) > %s
  FOR 5m
  LABELS {
	%s_receiver = "%s"
  }
  ANNOTATIONS {
	description = "服务 %s CPU使用率超过 %s",
	summary = "服务 %s CPU 使用率较高"
  }
`, repNs, repSvc, ns, svc, svc, threshold, svc, receiver, svc, threshold, svc)

	f.WriteString(rulesContent)
	return ""
}

//转换百分数
func traToPercent(num string) (bool, string) {

	intNum, _ := strconv.Atoi(num)
	if intNum >= 0 && intNum <= 1 {

		return true, strconv.Itoa(intNum * 100)
	}

	return false, "请输入一个0~1之间的小数"
}

func strReplace(ns, svc string) (repNs string, repSvc string) {

	repNs, repSvc = ns, svc
	if strings.Contains(repNs, "-") {
		repNs = strings.Replace(repNs, "-", "_", -1)
	}

	if strings.Contains(repSvc, "-") {
		repSvc = strings.Replace(repSvc, "-", "_", -1)
	}

	return

}

//配置文件中增加 exporter
func (h *Handler) addExternExporter(w http.ResponseWriter, r *http.Request) {
	var resp respMsg
	cfg := config.Config{}

	var exCfg = struct {
		JobName     string `json:"jobName"`
		MetricsPath string `json:"metricsPath"`
		Scheme      string `json:"scheme"`
		//TargetsURL  model.LabelValue `json:"targetsURL"`
		TargetsURL string `json:"targetsURL"`
	}{}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorln("解析BCM界面传参出错", err)
		resp.respFail(w, "界面参数配置出错")
	}
	json.Unmarshal(data, &exCfg)

	log.Infoln("解析BCM传来的数据为:", exCfg)

	yamlFile, err := ioutil.ReadFile(prometheusCfg)
	if err != nil {
		log.Errorln("error occured when read prometheus.yaml:", err)
		return
	}

	if err = yaml.Unmarshal(yamlFile, &cfg); err != nil {
		log.Errorln("error occured when unmarshal prometheus.yaml:", err)
		return
	}
	log.Infoln("程序中现有的配置内容是:", cfg)

	staticCfg := &config.TargetGroup{} //--0x112344
	//	var staticCfg *config.TargetGroup//--0x0000000
	//var staticCfg = &config.TargetGroup{} //0x223344
	labelSet := make(model.LabelSet, 0)

	log.Infoln("TargetsURL", exCfg.TargetsURL)
	//labelSet["targetsURL"] = model.LabelValue(exCfg.TargetsURL)
	labelSet[model.LabelName(exCfg.TargetsURL)] = "NOVALUE"
	log.Infoln("labelSet", labelSet)
	//labelSet["NOKEY"] = "NOVALUE"

	staticCfg.Targets = append(staticCfg.Targets, labelSet)
	staticCfg.Source = "1234567678"

	log.Infoln("Targets", staticCfg.Targets)

	addServiceDiscoveryCfg := config.ServiceDiscoveryConfig{}
	addServiceDiscoveryCfg.StaticConfigs = append(addServiceDiscoveryCfg.StaticConfigs, staticCfg)

	addOneScrapeCfg := &config.ScrapeConfig{
		JobName:                exCfg.JobName,
		MetricsPath:            exCfg.MetricsPath,
		Scheme:                 exCfg.Scheme,
		ServiceDiscoveryConfig: addServiceDiscoveryCfg,
	}

	log.Infoln("新增的外部服务配置是:", addOneScrapeCfg)

	cfg.ScrapeConfigs = append(cfg.ScrapeConfigs, addOneScrapeCfg)
	out, _ := yaml.Marshal(&cfg)
	f, _ := os.OpenFile(prometheusCfg, os.O_CREATE|os.O_RDWR, 0600)
	f.Write(out)

	log.Infoln("新增后的配置数据:", string(out))

	resp.respSucc(w, "操作成功")
	return
}

// 关于MEMORY的报警规则文件
func writeMemoryCfgToFile(ns, svc, receiver, threshold string) string {

	rulesDir := preLocation + ns + "/"
	rulesFileName := svc + "_" + memory + "_" + alertRules

	//如果路径不存在 则创建
	if err := createDir(rulesDir); err != nil {
		return "Memory规则文件路径创建失败"
	}

	//以服务为单位 增加CPU规则文件
	if errMsg := addRuleFiles(rulesDir + rulesFileName); errMsg != "" {
		return errMsg
	}

	f, err := os.OpenFile(rulesDir+rulesFileName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln("MEMORY 规则文件写入出错:", err)
		return "Memory规则文件打开出错"
	}
	defer f.Close()

	//规则文件不支持标识符"-"
	repNs, repSvc := strReplace(ns, svc)

	intThr, _ := strconv.Atoi(threshold)
	intThr = intThr * 1000000000 //1G

	rulesContent := fmt.Sprintf(`ALERT %s_%s_MemoryUsageHigh
  IF sum(container_memory_usage_bytes{namespace="%s",container_name="%s",pod_name=~"%s.*"}) > %s
  FOR 5m
  LABELS {
	%s_receiver = "%s"
  }
  ANNOTATIONS {
	description = "服务 %s 的内存使用率超过 %s",
	summary = "服务 %s 的内存使用率过高"
  }
`, repNs, repSvc, ns, svc, svc, intThr, svc, receiver, svc, threshold, svc)

	f.WriteString(rulesContent)
	return ""
}

// 关于服务状态的报警规则文件
func writeSvcStatusToFile(ns, svc, receiver string) string {

	rulesDir := preLocation + ns + "/"
	rulesFileName := svc + "_" + svcStatus + "_" + alertRules

	//如果路径不存在 则创建
	if err := createDir(rulesDir); err != nil {
		return "服务状态规则文件路径创建失败"
	}

	//以服务为单位 增加CPU规则文件
	if errMsg := addRuleFiles(rulesDir + rulesFileName); errMsg != "" {
		return errMsg
	}

	f, err := os.OpenFile(rulesDir+rulesFileName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln("SVC_STATUS 规则文件写入出错:", err)
		return "服务状态 规则文件打开出错"
	}
	defer f.Close()

	//规则文件不支持标识符"-"
	repNs, repSvc := strReplace(ns, svc)

	rulesContent := fmt.Sprintf(`ALERT %s_%s_Down
  IF absent(container_memory_usage_bytes{ namespace = "%s",pod_name =~ "%s.*",container_name = "%s"})
  FOR 5m
  LABELS {
	%s_receiver = "%s"
  }
  ANNOTATIONS {
    description = "服务 %s 宕机",
	summary = " 租户 %s 下的服务 %s 已宕机超过 %s 分钟 "
  }

ALERT %s_%s_PodRestarted
  IF kube_pod_container_status_restarts{namespace = "%s",pod =~"%s.*",container = "%s"} > 0 
  FOR 5m
  LABELS {
    %s_receiver = "%s"
  }
  ANNOTATIONS {
	summary = "服务 %s 发生重启",
	description = "租户 %s 下的服务 %s 发生重启事件"
  }
`, repNs, repSvc, ns, svc, svc, repSvc, receiver, svc, ns, svc, repNs, repSvc, ns, svc, svc, duration, repSvc, receiver, svc, ns, svc)

	f.WriteString(rulesContent)
	return ""
}

func threConvToInt(cThre, mThre string) (CPUThre int, memThre int) {

	CPUThre, _ = strconv.Atoi(cThre)
	memThre, _ = strconv.Atoi(mThre)

	return
}

func (h *Handler) updAlertForBCM(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	log.Infoln("BCM 更新监控对象配置....")

	var resp respMsg
	var alertTargets = struct {
		AlertJob          []string          `json:"alertJob"`                  //监控对象
		AlertSendType     map[string]string `json:"alertSendType"`             //报警发送方式
		Namespace         string            `json:"namespace"`                 //租户
		SvcName           string            `json:"svcName"`                   //服务
		Receiver          string            `json:"receiver"`                  //接收者
		AlertDurationTime string            `json:"alertDurationTime"`         //报警触发持续时间
		CPUThreshold      string            `json:"cpuThreshold,omitempty"`    //CPU配置
		MemoryThreshold   string            `json:"memoryThreshold,omitempty"` //Memory配置
	}{}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorln("解析BCM界面传参出错", err)
	}
	json.Unmarshal(data, &alertTargets)

	log.Infoln("解析BCM传来的数据为:", alertTargets)

	//删除旧配置，包括配置文件参数和规则文件
	delSvcMonitorCfg(alertTargets.Namespace, alertTargets.SvcName)

	//更新规则文件 写入新配置
	for _, target := range alertTargets.AlertJob {
		switch target {
		case cpu:
			if result := writeCPUCfgToFile(alertTargets.Namespace, alertTargets.SvcName,
				alertTargets.Receiver, alertTargets.CPUThreshold,
				alertTargets.AlertDurationTime); result != "" {
				resp.respFail(w, result)
				return
			}
		case memory:
			if result := writeMemoryCfgToFile(alertTargets.Namespace, alertTargets.SvcName,
				alertTargets.Receiver, alertTargets.MemoryThreshold,
				alertTargets.AlertDurationTime); result != "" {
				resp.respFail(w, result)
				return
			}
		default:
			if result := writeSvcStatusToFile(alertTargets.Namespace, alertTargets.SvcName,
				alertTargets.Receiver, alertTargets.AlertDurationTime); result != "" {
				resp.respFail(w, result)
				return
			}
		}
	}
	//重启prometheus 使配置生效
	PromReloadChan <- "reload the proCfg!"

	//重启配置文件
	//与alertmanager 通信 执行更新操作
	recSvcInfo := receiverInfo{
		OldReceiver: alertTargets.SvcName +
			"_" +
			getSvcReceiverMap(alertTargets.SvcName),
		NewReceiver: alertTargets.SvcName +
			"_" +
			alertTargets.Receiver,
		SvcName: alertTargets.SvcName,
	}

	//更新之前的map信息
	log.Infoln("更新前的map信息是:", getAllMapSvcRecInfo())

	//与alertmanager通信
	sendUpdataToAlert(alertTargets.AlertSendType, recSvcInfo)

	//更新 最新的map信息
	updSvcReceiverMap(alertTargets.SvcName, alertTargets.Receiver)

	//打印map信息
	log.Infoln("更新后的map信息是:", getAllMapSvcRecInfo())
	resp.respSucc(w, "操作成功")
	return

}

func delSvcMonitorCfg(ns, svc string) {

	//先删除所有的配置 包括参数配置和文件配置
	rulesDir := preLocation + ns + "/"

	//SvcStatus
	SRulesFileName := svc + "_" + cpu + "_" + alertRules
	delRuleFiles(rulesDir + SRulesFileName)

	//memory
	MRulesFileName := svc + "_" + memory + "_" + alertRules
	delRuleFiles(rulesDir + MRulesFileName)

	//CPU
	CRulesFileName := svc + "_" + svcStatus + "_" + alertRules
	delRuleFiles(rulesDir + CRulesFileName)
}

type receiverInfo struct {
	OldReceiver string
	NewReceiver string
	SvcName     string
}

// 与alertmanager通信 发送更新信息
func sendUpdataToAlert(alertType map[string]string, recSvcInfo receiverInfo) {
	var (
		req  Request
		resp respInfo

		recInfo struct {
			LabelInfo receiverInfo      `json:"labelInfo"`
			AlertType map[string]string `json:"alertType"` //alert告警接收者使用
		}
	)

	recInfo.AlertType = make(map[string]string, 0)
	recInfo.AlertType = alertType
	recInfo.LabelInfo = recSvcInfo

	req = Request{
		URL:     getInitCfg().AlertManagerURL + reload,
		Content: recInfo,
		Type:    "PUT",
	}

	log.Infoln("与alertmanager通信的内容是：", req.Content)
	log.Infoln("与alertmanager通信的URL：", req.URL)

	data, err := req.SendRequestByJSON()
	if err != nil {
		log.Errorln("通信失败：", err)
		return
	}
	json.Unmarshal(data, &resp)
	//返回200表示成功 400错误
	log.Infoln("alertmanager 返回的通信结果是:", resp)
}

func (h *Handler) delAlertForBCM(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	log.Infoln("BCM 删除监控对象配置....")

	var resp respMsg
	reqMsg := struct {
		Namespace string `json:"namespace"`
		SvcName   string `json:"svcName"`
		Receiver  string
	}{}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorln("解析BCM界面传参出错", err)
	}
	json.Unmarshal(data, &reqMsg)

	//从map中获取服务的接收者信息
	reqMsg.Receiver = getSvcReceiverMap(reqMsg.SvcName)

	log.Info("从map中获取的接收者信息是:", reqMsg.Receiver)
	log.Infoln("解析BCM传来的数据为:", reqMsg)

	//删除旧配置，包括配置文件参数和规则文件
	delSvcMonitorCfg(reqMsg.Namespace, reqMsg.SvcName)

	//重启prometheus 使配置生效
	PromReloadChan <- "reload the proCfg!"

	//删除map中服务对应的接收者
	delSvcReceiverFromMap(reqMsg.SvcName)

	//与alertmanager通信 删除alertmanager 相应信息
	sendDelMsgToAlertmanager(reqMsg.Receiver, reqMsg.SvcName)
	resp.respSucc(w, "操作成功")
	return

}

func sendDelMsgToAlertmanager(receiver, preLabel string) {
	log.Infoln("发送消息给alertmanager 删除相应信息")

	var (
		req  Request
		resp respInfo
	)
	var sendInfo = struct {
		LabelInfo recLabel `json:"labelInfo"`
		//	AlertType map[string]string `json:"alertType"`
	}{}

	//	sendInfo.AlertType = make(map[string]string, 0)
	sendInfo.LabelInfo.Match = make(map[string]string, 0)

	//sendInfo.AlertType = alertType

	sendInfo.LabelInfo = recLabel{
		Match: map[string]string{
			preLabel + "_" + "receiver": receiver,
		},
		Receiver: preLabel + "_" + receiver,
	}
	log.Infoln("&&&&删除时 发给alertmanager的数据是&&&&:", sendInfo)
	req = Request{
		URL:     getInitCfg().AlertManagerURL + reload,
		Content: sendInfo,
		Type:    "DELETE",
	}

	log.Infoln("与alertmanager通信的内容是：", req.Content)
	log.Infoln("与alertmanager通信的URL：", req.URL)

	data, err := req.SendRequestByJSON()
	if err != nil {
		log.Errorln("通信失败：", err)
		return
	}
	json.Unmarshal(data, &resp)
	log.Infoln("与alertmanager通信的结果是:", resp)
	return
}

func delRuleFiles(fileName string) {
	//先删除prometheus配置中的规则文件参数
	log.Infoln("删除的配置文件是:", fileName)
	currentCfg, _ := config.LoadFile(CFile)
	log.Infoln("***当前的配置文件是:***", currentCfg)

	for i, v := range currentCfg.RuleFiles {
		log.Infoln("***配置中存在的规则文件是:***", v)
		if v == fileName {
			currentCfg.RuleFiles = append(currentCfg.RuleFiles[:i], currentCfg.RuleFiles[i+1:]...)
			log.Infoln("***删除后的配置文件是:***", currentCfg)
			//重写配置前 先删除之前的配置
			os.RemoveAll(prometheusCfg)

			out, _ := yaml.Marshal(&currentCfg)
			f, err := os.OpenFile(prometheusCfg, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				log.Errorln("文件打开出错:", err)
				return
			}
			defer f.Close()
			f.Write(out)
			break
		}
	}
	//再删除具体的规则文件
	os.RemoveAll(fileName)
	log.Infoln("文件", fileName, "已经删除")
}

//monitor for k8s cluster info
func (h *Handler) creNodesInfo(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	log.Infoln("BCM 启动集群监控....")

	var resp respMsg
	var alertTargets = struct {
		AlertJob      []string          `json:"alertJob"`      //监控对象 包括 cpu memory disk
		AlertSendType map[string]string `json:"alertSendType"` //报警发送方式
		Receiver      string            `json:"receiver"`      //接收者
		//AlertDurationTime string            `json:"alertDurationTime"`         //报警触发持续时间,默认5m
		CPUThreshold    string `json:"cpuThreshold,omitempty"`    //CPU阈值,根据监控对象填写
		MemoryThreshold string `json:"memoryThreshold,omitempty"` //Memory阈值,根据监控对象填写
	}{}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorln("解析BCM界面传参出错", err)
	}
	json.Unmarshal(data, &alertTargets)

	//阈值限定0~1
	CPUThre, memThre := threConvToInt(alertTargets.CPUThreshold, alertTargets.MemoryThreshold)
	if CPUThre > 1 || CPUThre < 0 {
		resp.respFail(w, "CPU阈值为0~1之间的小数")

		return
	}

	if memThre > 1 || memThre < 0 {
		resp.respFail(w, "MEMORY阈值为0~1之间的小数")

		return
	}

	//增加报警配置
	for _, target := range alertTargets.AlertJob {
		switch target {
		case cpu:
			if result := wNodeCPUCfg(
				alertTargets.CPUThreshold, alertTargets.Receiver); result != "" {
				resp.respFail(w, result)
				return
			}
		case memory:
			if result := wNodeMemoryCfg(
				alertTargets.MemoryThreshold, alertTargets.Receiver); result != "" {
				resp.respFail(w, result)
				return
			}
		default:
			if result := wNodeDiskCfg(
				alertTargets.Receiver); result != "" {
				resp.respFail(w, result)
				return
			}
		}
	}

	//重启prometheus 使配置生效
	PromReloadChan <- "reload the proCfg!"

	//保存节点信息
	addSvcReceiverToMap(clusterAlertReceiver, alertTargets.Receiver)
	//与 alertmanager 通信
	sendMsgToAlert(alertTargets.AlertSendType, alertTargets.Receiver, k8sCluster)
	resp.respSucc(w, "操作成功")
	return
}

func wNodeCPUCfg(threshold, receiver string) string {
	rulesDir := preLocation + k8sCluster + "/"
	rulesFileName := nodeCPU + "_" + alertRules

	//如果路径不存在 则创建
	if err := createDir(rulesDir); err != nil {
		return "CPU规则路径创建失败"
	}

	//以服务为单位 增加CPU规则文件
	if errMsg := addRuleFiles(rulesDir + rulesFileName); errMsg != "" {
		return errMsg
	}

	f, err := os.OpenFile(rulesDir+rulesFileName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln("CPU 规则文件写入出错:", err)
		return "CPU报警规则写入出错"
	}
	defer f.Close()

	rulesContent := fmt.Sprintf(`ALERT NodeCPUUsageHigh
	IF ((sum(node_cpu{mode=~"user|nice|system|irq|softirq|steal|idle|iowait"})by(instance)) - (sum(node_cpu{mode=~"idle|iowait"})by(instance)))  / (sum(node_cpu{mode=~"user|nice|system|irq|softirq|steal|idle|iowait"})by(instance))   > %s
  FOR 5m
  LABELS {
	%s_receiver = "%s"
  }
  ANNOTATIONS {
    description = "主机{{ $labels.instance }}  CPU使用率超过 %s",
	summary = "主机 {{ $labels.instance }} CPU使用率较高"
  }
`, threshold, k8sCluster, receiver, threshold)

	f.WriteString(rulesContent)
	return ""
}

func wNodeMemoryCfg(threshold, receiver string) string {
	rulesDir := preLocation + k8sCluster + "/"
	rulesFileName := nodeMemory + "_" + alertRules

	//如果路径不存在 则创建
	if err := createDir(rulesDir); err != nil {
		return "MEMORY规则路径创建失败"
	}

	if errMsg := addRuleFiles(rulesDir + rulesFileName); errMsg != "" {
		return errMsg
	}

	f, err := os.OpenFile(rulesDir+rulesFileName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln("MEMORY 规则文件写入出错:", err)
		return "MEMORY报警规则写入出错"
	}
	defer f.Close()

	rulesContent := fmt.Sprintf(`ALERT NodeMemoryUsageHigh
	IF (sum(node_memory_MemTotal)BY(instance) - sum(node_memory_MemFree + node_memory_Buffers + node_memory_Cached)BY(instance)) / sum(node_memory_MemTotal)BY(instance)  > %s
  FOR 5m
  LABELS {
	%s_receiver = "%s"
  }
  ANNOTATIONS {
    description = "主机 {{ $labels.instance }} 内存使用率超过 %s ",
	summary = "主机 {{ $labels.instance }} 内存使用率较高"
  }
`, threshold, k8sCluster, receiver, threshold)

	f.WriteString(rulesContent)
	return ""

}

func wNodeDiskCfg(receiver string) string {
	rulesDir := preLocation + k8sCluster + "/"
	rulesFileName := nodeDisk + "_" + alertRules

	//如果路径不存在 则创建
	if err := createDir(rulesDir); err != nil {
		return "disk规则路径创建失败"
	}

	//以服务为单位 增加CPU规则文件
	if errMsg := addRuleFiles(rulesDir + rulesFileName); errMsg != "" {
		return errMsg
	}

	f, err := os.OpenFile(rulesDir+rulesFileName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Errorln("disk 规则文件写入出错:", err)
		return "disk报警规则写入出错"
	}
	defer f.Close()

	rulesContent := fmt.Sprintf(`ALERT NodeDiskWillFillIn4Hours
  IF predict_linear(node_filesystem_free[1h], 4*3600) < 0
  FOR 5m 
  LABELS {
	%s_receiver = "%s"
  }
  ANNOTATIONS {
    description = "主机 {{ $labels.instance }} 磁盘剩余空间较少 }}",
	summary = "主机 {{ $labels.instance }} 磁盘剩余空间较少"
  }
`, k8sCluster, receiver)

	f.WriteString(rulesContent)
	return ""
}

func delNodesMonitorInfo() {

	rulesDir := preLocation + k8sCluster + "/"

	//删除磁盘监控配置信息
	diskRulesFile := nodeDisk + "_" + alertRules
	delRuleFiles(rulesDir + diskRulesFile)

	//删除cpu监控配置信息
	CPURulesFile := nodeCPU + "_" + alertRules
	delRuleFiles(rulesDir + CPURulesFile)

	//删除内存监控配置信息
	memoryRulesFile := nodeMemory + "_" + alertRules
	delRuleFiles(rulesDir + memoryRulesFile)
}

func (h *Handler) updNodesInfo(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	log.Infoln("BCM 删除集群主机监控配置....")

	var resp respMsg
	var alertTargets = struct {
		AlertJob      []string          `json:"alertJob"`      //监控对象 包括 cpu memory disk
		AlertSendType map[string]string `json:"alertSendType"` //报警发送方式
		Receiver      string            `json:"receiver"`      //接收者
		//AlertDurationTime string            `json:"alertDurationTime"`         //报警触发持续时间,默认5m
		CPUThreshold    string `json:"cpuThreshold,omitempty"`    //CPU阈值,根据监控对象填写
		MemoryThreshold string `json:"memoryThreshold,omitempty"` //Memory阈值,根据监控对象填写
	}{}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorln("解析BCM界面传参出错", err)
	}
	json.Unmarshal(data, &alertTargets)

	//阈值限定0~1
	CPUThre, memThre := threConvToInt(alertTargets.CPUThreshold, alertTargets.MemoryThreshold)
	if CPUThre > 1 || CPUThre < 0 {
		resp.respFail(w, "CPU阈值为0~1之间的小数")

		return
	}

	if memThre > 1 || memThre < 0 {
		resp.respFail(w, "MEMORY阈值为0~1之间的小数")

		return
	}

	//删除旧配置，包括配置文件参数和规则文件
	delNodesMonitorInfo()

	//更新报警配置
	for _, target := range alertTargets.AlertJob {
		switch target {
		case cpu:
			if result := wNodeCPUCfg(alertTargets.AlertDurationTime,
				alertTargets.CPUThreshold, alertTargets.Receiver); result != "" {
				resp.respFail(w, result)
				return
			}
		case memory:
			if result := wNodeMemoryCfg(alertTargets.AlertDurationTime,
				alertTargets.MemoryThreshold, alertTargets.Receiver); result != "" {
				resp.respFail(w, result)
				return
			}
		default:
			if result := wNodeDiskCfg(alertTargets.AlertDurationTime,
				alertTargets.Receiver); result != "" {
				resp.respFail(w, result)
				return
			}
		}
	}

	//重启prometheus 使配置生效
	PromReloadChan <- "reload the proCfg!"

	//重启配置文件
	//与alertmanager 通信 执行更新操作
	recSvcInfo := receiverInfo{
		OldReceiver: k8sCluster + "_" + getSvcReceiverMap(clusterAlertReceiver),
		NewReceiver: k8sCluster + "_" + alertTargets.Receiver,
		SvcName:     k8sCluster,
	}

	//更新之前的map信息
	log.Infoln("更新前的map信息是:", getAllMapSvcRecInfo())

	//与alertmanager通信
	sendUpdataToAlert(alertTargets.AlertSendType, recSvcInfo)

	//更新 最新的map信息
	updSvcReceiverMap(clusterAlertReceiver, alertTargets.Receiver)

	//打印map信息
	log.Infoln("更新后的map信息是:", getAllMapSvcRecInfo())
	resp.respSucc(w, "操作成功")
	return
}

func (h *Handler) delNodesInfo(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	log.Infoln("BCM 删除集群主机监控配置....")

	var resp respMsg
	delNodesMonitorInfo()

	//重启prometheus 使配置生效
	PromReloadChan <- "reload the proCfg!"

	//与alertmanager通信 删i除alertmanager 相应信息
	receiver := getSvcReceiverMap(clusterAlertReceiver)
	preLabel := k8sCluster

	sendDelMsgToAlertmanager(receiver, preLabel)

	//删除map中服务对应的接收者
	delSvcReceiverFromMap(clusterAlertReceiver)

	resp.respSucc(w, "操作成功")
	return
}

func (h *Handler) config(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	h.executeTemplate(w, "config.html", h.configString)
}

func (h *Handler) rules(w http.ResponseWriter, r *http.Request) {
	h.executeTemplate(w, "rules.html", h.ruleManager)
}

func (h *Handler) targets(w http.ResponseWriter, r *http.Request) {
	// Bucket targets by job label
	tps := map[string][]*retrieval.Target{}
	for _, t := range h.targetManager.Targets() {
		job := string(t.Labels()[model.JobLabel])
		tps[job] = append(tps[job], t)
	}

	for _, targets := range tps {
		sort.Slice(targets, func(i, j int) bool {
			return targets[i].Labels()[model.InstanceLabel] < targets[j].Labels()[model.InstanceLabel]
		})
	}

	h.executeTemplate(w, "targets.html", struct {
		TargetPools map[string][]*retrieval.Target
	}{
		TargetPools: tps,
	})
}

func (h *Handler) version(w http.ResponseWriter, r *http.Request) {
	dec := json.NewEncoder(w)
	if err := dec.Encode(h.versionInfo); err != nil {
		http.Error(w, fmt.Sprintf("error encoding JSON: %s", err), http.StatusInternalServerError)
	}
}

func (h *Handler) quit(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Requesting termination... Goodbye!")
	close(h.quitCh)
}

func (h *Handler) reload(w http.ResponseWriter, r *http.Request) {
	rc := make(chan error)
	h.reloadCh <- rc
	if err := <-rc; err != nil {
		http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
	}
}

func (h *Handler) consolesPath() string {
	if _, err := os.Stat(h.options.ConsoleTemplatesPath + "/index.html"); !os.IsNotExist(err) {
		return h.options.ExternalURL.Path + "/consoles/index.html"
	}
	if h.options.UserAssetsPath != "" {
		if _, err := os.Stat(h.options.UserAssetsPath + "/index.html"); !os.IsNotExist(err) {
			return h.options.ExternalURL.Path + "/user/index.html"
		}
	}
	return ""
}

func tmplFuncs(consolesPath string, opts *Options) template_text.FuncMap {
	return template_text.FuncMap{
		"since": func(t time.Time) time.Duration {
			return time.Since(t) / time.Millisecond * time.Millisecond
		},
		"consolesPath": func() string { return consolesPath },
		"pathPrefix":   func() string { return opts.ExternalURL.Path },
		"buildVersion": func() string { return opts.Version.Revision },
		"stripLabels": func(lset model.LabelSet, labels ...model.LabelName) model.LabelSet {
			for _, ln := range labels {
				delete(lset, ln)
			}
			return lset
		},
		"globalURL": func(u *url.URL) *url.URL {
			host, port, err := net.SplitHostPort(u.Host)
			if err != nil {
				return u
			}
			for _, lhr := range localhostRepresentations {
				if host == lhr {
					_, ownPort, err := net.SplitHostPort(opts.ListenAddress)
					if err != nil {
						return u
					}

					if port == ownPort {
						// Only in the case where the target is on localhost and its port is
						// the same as the one we're listening on, we know for sure that
						// we're monitoring our own process and that we need to change the
						// scheme, hostname, and port to the externally reachable ones as
						// well. We shouldn't need to touch the path at all, since if a
						// path prefix is defined, the path under which we scrape ourselves
						// should already contain the prefix.
						u.Scheme = opts.ExternalURL.Scheme
						u.Host = opts.ExternalURL.Host
					} else {
						// Otherwise, we only know that localhost is not reachable
						// externally, so we replace only the hostname by the one in the
						// external URL. It could be the wrong hostname for the service on
						// this port, but it's still the best possible guess.
						host, _, err := net.SplitHostPort(opts.ExternalURL.Host)
						if err != nil {
							return u
						}
						u.Host = host + ":" + port
					}
					break
				}
			}
			return u
		},
		"healthToClass": func(th retrieval.TargetHealth) string {
			switch th {
			case retrieval.HealthUnknown:
				return "warning"
			case retrieval.HealthGood:
				return "success"
			default:
				return "danger"
			}
		},
		"alertStateToClass": func(as rules.AlertState) string {
			switch as {
			case rules.StateInactive:
				return "success"
			case rules.StatePending:
				return "warning"
			case rules.StateFiring:
				return "danger"
			default:
				panic("unknown alert state")
			}
		},
	}
}

func (h *Handler) getTemplate(name string) (string, error) {
	baseTmpl, err := ui.Asset("web/ui/templates/_base.html")
	if err != nil {
		return "", fmt.Errorf("error reading base template: %s", err)
	}
	pageTmpl, err := ui.Asset(filepath.Join("web/ui/templates", name))
	if err != nil {
		return "", fmt.Errorf("error reading page template %s: %s", name, err)
	}
	return string(baseTmpl) + string(pageTmpl), nil
}

func (h *Handler) executeTemplate(w http.ResponseWriter, name string, data interface{}) {
	text, err := h.getTemplate(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	tmpl := template.NewTemplateExpander(h.context, text, name, data, h.now(), h.queryEngine, h.options.ExternalURL)
	tmpl.Funcs(tmplFuncs(h.consolesPath(), h.options))

	result, err := tmpl.ExpandHTML(nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, result)
}

func dumpHeap(w http.ResponseWriter, r *http.Request) {
	target := fmt.Sprintf("/tmp/%d.heap", time.Now().Unix())
	f, err := os.Create(target)
	if err != nil {
		log.Error("Could not dump heap: ", err)
	}
	fmt.Fprintf(w, "Writing to %s...", target)
	defer f.Close()
	pprof_runtime.WriteHeapProfile(f)
	fmt.Fprintf(w, "Done")
}

// AlertStatus bundles alerting rules and the mapping of alert states to row classes.
type AlertStatus struct {
	AlertingRules        []*rules.AlertingRule
	AlertStateToRowClass map[rules.AlertState]string
}

type byAlertStateAndNameSorter struct {
	alerts []*rules.AlertingRule
}

func (s byAlertStateAndNameSorter) Len() int {
	return len(s.alerts)
}

func (s byAlertStateAndNameSorter) Less(i, j int) bool {
	return s.alerts[i].State() > s.alerts[j].State() ||
		(s.alerts[i].State() == s.alerts[j].State() &&
			s.alerts[i].Name() < s.alerts[j].Name())
}

func (s byAlertStateAndNameSorter) Swap(i, j int) {
	s.alerts[i], s.alerts[j] = s.alerts[j], s.alerts[i]
}
