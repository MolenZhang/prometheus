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
	"strings"
	"sync"
	"time"

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

	router.Post("/promcfgreload", h.reloadpromcfg)
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

func (h *Handler) reloadpromcfg(w http.ResponseWriter, r *http.Request) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	//defer close(PromReloadChan)
	fmt.Println("界面开始重置prometheus 配置文件！！！！")
	pCfg := promCfg{}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("Molen_failed to receive the data from web:", err)
	}
	json.Unmarshal(data, &pCfg)

	fmt.Println("Molen_the data from the web is：", pCfg)
	//全局配置
	if err := promCfgForGlobal(&pCfg); err != nil {
		http.Error(w, "failed to create config file", http.StatusInternalServerError)
		fmt.Println("Molen_failed to create config file...")
		return
	}

	if len(pCfg.DataSourceFromK8s) == 0 && len(pCfg.DataSourceFromOthers) == 0 {
		http.Error(w, "DataSource 不可为空", http.StatusInternalServerError)
		fmt.Println("DataSourceFromK8s or DataSourceFromOthers is null")
		return
	}

	//关于其他监控对象的配置操作
	if len(pCfg.DataSourceFromOthers) != 0 {
		fmt.Println("读取配置中关于其他配置的数据信息:", pCfg.DataSourceFromOthers)
		if err := promCfgForOthers(&pCfg); err != nil {
			http.Error(w, "failed to create config file", http.StatusInternalServerError)
			fmt.Println("Molen_failed to create config file...")
			return
		}
		resp, _ := json.Marshal("其他监控配置创建成功")
		w.Write(resp)

		//发送重启信号
		PromReloadChan <- "reload the proCfg!"
		fmt.Println("Molen_Done to relaod the prometheus configuration")

		return
	}
	//关于监控k8s的配置操作
	fmt.Println("读取配置中关于k8s配置的数据信息:", pCfg.DataSourceFromK8s)
	if err := promCfgForK8s(&pCfg); err != nil {
		http.Error(w, "failed to create config file", http.StatusInternalServerError)
		fmt.Println("Molen_failed to create config file...")
		return
	}
	resp, _ := json.Marshal("k8s监控配置创建成功")
	w.Write(resp)

	//发送重启信号
	PromReloadChan <- "reload the proCfg!"
	fmt.Println("Molen_Done to relaod the prometheus configuration")
	return
}

//Molen: 主要是定义界面需要配置的数据参数
type promCfg struct {
	ScrapeInterval       string             `json:"scrape_interval,omitempty"` //采集数据的频率 默认20s
	ScrapeTimeout        string             `json:"scrape_timeout"`            //数据抓取超时时间   默认10s
	EvaluationInterval   string             `json:"evaluation_interval"`       //规则计算频率   默认20s
	DataSourceFromK8s    []KubernetesTarget `json:"data_source_from_kubernetes,omitempty"`
	DataSourceFromOthers []OtherTarget      `json:"data_source_from_others,omitempty"`
}

type KubernetesTarget struct {
	JobName       string `json:"job_name"`
	K8sMasterHost string `json:"kubernetes_master_host"` //k8s master address
	Role          string `json:"role"`
	//TargetPort    string `json:"target_port"` //抓取数据指标的监听端口 只显示 不可配, 回复node_container:10255;node:9100
}

type OtherTarget struct {
	JobName       string `json:"job_name"`
	ScrapeAddress string `json:"scrape_address"` //数据抓取的地址，例如：172.16.13.111:30921
}

func promCfgForGlobal(pCfg *promCfg) error {
	//全局配置
	fout, err := os.Create("/etc/newprometheus.yaml")
	if err != nil {
		fmt.Println("配置文件打开出错:", err)
		return err
	}
	defer fout.Close()

	cfgContent := fmt.Sprintf(`global:
  scrape_interval: %s
  scrape_timeout: %s
  evaluation_interval: %s
scrape_configs:`, pCfg.ScrapeInterval, pCfg.ScrapeTimeout, pCfg.EvaluationInterval)
	fout.WriteString(cfgContent)
	return nil
}

func promCfgForK8s(pCfg *promCfg) error {

	for k := range pCfg.DataSourceFromK8s {
		fout, err := os.OpenFile("/etc/newprometheus.yaml", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
		if err != nil {
			fmt.Println("config file not exist:", err)
			return err
		}
		var cfgContentAppend string
		//抓取k8s集群节点信息
		if pCfg.DataSourceFromK8s[k].Role == "node" {
			cfgContentAppend = fmt.Sprintf(`- job_name: %s
  kubernetes_sd_configs:
  - role: %s
    api_servers:
	- %s
  relabel_configs:
  - action: labelmap
    regex: __meta_kubernetes_node_label_(.+)
  - source_labels: [__address__]
   	regex: '(.*):10250'
	replacement: '${1}:9100'
	target_label: __address__
  - source_labels: [__meta_kubernetes_node_address_InternalIP]
	action: replace
	target_label: internalIP`, pCfg.DataSourceFromK8s[k].Role, pCfg.DataSourceFromK8s[k].K8sMasterHost)
		}
		//抓取k8s集群各个容器的信息
		if pCfg.DataSourceFromK8s[k].Role == "container" { //源码中严格意义上并没有containe 的 role
			cfgContentAppend = fmt.Sprintf(`- job_name: %s
  kubernetes_sd_configs:
  - role: node
    api_servers:
	- %s
  relabel_configs:
  - source_labels: [__meta_kubernetes_node_address_InternalIP]
    action: replace
	target_label: nodeIP
  - source_labels: [__meta_kubernetes_node_label_kubernetes_io_hostname]
    action: replace
	target_label: nodeName
  - source_labels: [__address__]
    regex: '(.*):10250'
	replacement: '${1}:10255
	itarget_label: __address__'`, pCfg.DataSourceFromK8s[k].K8sMasterHost)
		}
		fout.WriteString("\n")
		fout.WriteString(cfgContentAppend)
	}
	return nil
}

func promCfgForOthers(pCfg *promCfg) error {

	for k := range pCfg.DataSourceFromOthers {
		fout, err := os.OpenFile("/etc/newprometheus.yaml", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
		if err != nil {
			fmt.Println("config file not exist:", err)
			return err
		}
		cfgContentAppend := fmt.Sprintf(`- job_name: %s
  static_configs:
  - targets: [%s]`, pCfg.DataSourceFromOthers[k].JobName, pCfg.DataSourceFromOthers[k].ScrapeAddress)
		fout.WriteString("\n")
		fout.WriteString(cfgContentAppend)
	}
	return nil
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
