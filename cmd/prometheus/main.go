// Copyright 2015 The Prometheus Authors
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

// The main package for the Prometheus server executable.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Comment this line to disable pprof endpoint.
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/emicklei/go-restful"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"golang.org/x/net/context"

	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/notifier"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/retrieval"
	"github.com/prometheus/prometheus/rules"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/fanin"
	"github.com/prometheus/prometheus/storage/local"
	"github.com/prometheus/prometheus/storage/remote"
	"github.com/prometheus/prometheus/web"
)

func main() {
	os.Exit(Main())
}

// defaultGCPercent is the value used to to call SetGCPercent if the GOGC
// environment variable is not set or empty. The value here is intended to hit
// the sweet spot between memory utilization and GC effort. It is lower than the
// usual default of 100 as a lot of the heap in Prometheus is used to cache
// memory chunks, which have a lifetime of hours if not days or weeks.
const defaultGCPercent = 40

var (
	configSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "prometheus",
		Name:      "config_last_reload_successful",
		Help:      "Whether the last configuration reload attempt was successful.",
	})
	configSuccessTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "prometheus",
		Name:      "config_last_reload_success_timestamp_seconds",
		Help:      "Timestamp of the last successful configuration reload.",
	})
)

func init() {
	prometheus.MustRegister(version.NewCollector("prometheus"))

	//Molen
	ws := new(restful.WebService)
	ws.
		Path("/promcfgreload").
		Consumes(restful.MIME_XML, restful.MIME_JSON).
		Produces(restful.MIME_JSON, restful.MIME_XML)

	ws.Route(ws.POST("/").To(promCfgReload).
		Doc("reload prometheus config").
		Operation("promCfgReload"))

	restful.Add(ws)
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

	if len(pCfg.DataSourceFromK8s) != 0 {
		err := errors.New("DataSource not found")
		fmt.Println(err)
		return err
	}
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
	target_label: __address__'`, pCfg.DataSourceFromK8s[k].K8sMasterHost)

		}
		fout.WriteString("\n")
		fout.WriteString(cfgContentAppend)
	}
	return nil
}

func promCfgForOthers(pCfg *promCfg) error {

	if len(pCfg.DataSourceFromOthers) != 0 {
		err := errors.New("DataSource not found")
		fmt.Println(err)
		return err
	}

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

//Molen
func promCfgReload(request *restful.Request, response *restful.Response) {
	fmt.Println("界面开始重置prometheus 配置文件！！！！")

	pCfg := promCfg{}
	if err := request.ReadEntity(pCfg); err != nil {
		response.WriteError(http.StatusInternalServerError, err)
		return
	}

	//全局配置
	if err := promCfgForGlobal(&pCfg); err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "failed to create config file")
		return
	}

	//关于其他监控对象的配置操作
	if err := promCfgForOthers(&pCfg); err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "failed to create config file")
		return
	}

	//关于监控k8s的配置操作
	if err := promCfgForK8s(&pCfg); err != nil {
		response.WriteErrorString(http.StatusInternalServerError, "failed to create config file")
		return
	}

}

//Molen: 主要是定义界面需要配置的数据参数
type promCfg struct {
	ScrapeInterval       string             `json:"scrape_interval,omitempty"` //采集数据的频率 默认20s
	ScrapeTimeout        string             `json:"scrape_timeout"`            //数据抓取超时时间	默认10s
	EvaluationInterval   string             `json:"evaluation_interval"`       //规则计算频率	默认20s
	DataSourceFromK8s    []KubernetesTarget `json:"data_source_from_kubernetes,omitempty"`
	DataSourceFromOthers []OtherTarget      `json:"data_source_from_others,omitempty"`
}

type KubernetesTarget struct {
	JobName       string `json:"job_name"`
	K8sMasterHost string `json:"kubernetes_master_host"` //k8s master address
	Role          string `json:"role"`
	//TargetPort    string `yaml:"target_port"` //抓取数据指标的监听端口 只显示 不可配, 回复node_container:10255;node:9100
}

type OtherTarget struct {
	JobName       string `json:"job_name"`
	ScrapeAddress string `json:"scrape_address"` //数据抓取的地址，例如：172.16.13.111:30921
}

// Main manages the startup and shutdown lifecycle of the entire Prometheus server.
func Main() int {
	if err := parse(os.Args[1:]); err != nil {
		log.Error(err)
		return 2
	}

	if cfg.printVersion {
		fmt.Fprintln(os.Stdout, version.Print("prometheus"))
		return 0
	}

	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(defaultGCPercent)
	}

	log.Infoln("Starting prometheus", version.Info())
	log.Infoln("Build context", version.BuildContext())
	log.Infoln("Host details", Uname())

	var (
		sampleAppender = storage.Fanout{}
		reloadables    []Reloadable
	)

	var localStorage local.Storage
	switch cfg.localStorageEngine {
	case "persisted":
		localStorage = local.NewMemorySeriesStorage(&cfg.storage)
		sampleAppender = storage.Fanout{localStorage}
	case "none":
		localStorage = &local.NoopStorage{}
	default:
		log.Errorf("Invalid local storage engine %q", cfg.localStorageEngine)
		return 1
	}

	remoteAppender := &remote.Writer{}
	sampleAppender = append(sampleAppender, remoteAppender)
	remoteReader := &remote.Reader{}
	reloadables = append(reloadables, remoteAppender, remoteReader)

	queryable := fanin.Queryable{
		Local:  localStorage,
		Remote: remoteReader,
	}

	var (
		notifier       = notifier.New(&cfg.notifier, log.Base())
		targetManager  = retrieval.NewTargetManager(sampleAppender, log.Base())
		queryEngine    = promql.NewEngine(queryable, &cfg.queryEngine)
		ctx, cancelCtx = context.WithCancel(context.Background())
	)

	ruleManager := rules.NewManager(&rules.ManagerOptions{
		SampleAppender: sampleAppender,
		Notifier:       notifier,
		QueryEngine:    queryEngine,
		Context:        fanin.WithLocalOnly(ctx),
		ExternalURL:    cfg.web.ExternalURL,
	})

	cfg.web.Context = ctx
	cfg.web.Storage = localStorage
	cfg.web.QueryEngine = queryEngine
	cfg.web.TargetManager = targetManager
	cfg.web.RuleManager = ruleManager
	cfg.web.Notifier = notifier

	cfg.web.Version = &web.PrometheusVersion{
		Version:   version.Version,
		Revision:  version.Revision,
		Branch:    version.Branch,
		BuildUser: version.BuildUser,
		BuildDate: version.BuildDate,
		GoVersion: version.GoVersion,
	}

	cfg.web.Flags = map[string]string{}
	cfg.fs.VisitAll(func(f *flag.Flag) {
		cfg.web.Flags[f.Name] = f.Value.String()
	})

	webHandler := web.New(&cfg.web)

	reloadables = append(reloadables, targetManager, ruleManager, webHandler, notifier)

	if err := reloadConfig(cfg.configFile, reloadables...); err != nil {
		log.Errorf("Error loading config: %s", err)
		return 1
	}

	// Wait for reload or termination signals. Start the handler for SIGHUP as
	// early as possible, but ignore it until we are ready to handle reloading
	// our config.
	hup := make(chan os.Signal)
	hupReady := make(chan bool)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		<-hupReady
		for {
			select {
			case <-hup:
				if err := reloadConfig(cfg.configFile, reloadables...); err != nil {
					log.Errorf("Error reloading config: %s", err)
				}
			case rc := <-webHandler.Reload():
				fmt.Println("Molen: 启用自带reload函数重启配置文件")
				if err := reloadConfig(cfg.configFile, reloadables...); err != nil {
					log.Errorf("Error reloading config: %s", err)
					rc <- err
				} else {
					rc <- nil
				}
			}
		}
	}()

	//Molen
	go func() {
		for {
			chanData, ok := <-web.PromReloadChan
			if !ok {
				return
			}
			fmt.Println("Molen_receive an channel signal:", chanData)
			reloadConfig("/etc/newprometheus.yaml", reloadables...)
		}

	}()
	// Start all components. The order is NOT arbitrary.

	if err := localStorage.Start(); err != nil {
		log.Errorln("Error opening memory series storage:", err)
		return 1
	}
	defer func() {
		if err := localStorage.Stop(); err != nil {
			log.Errorln("Error stopping storage:", err)
		}
	}()

	defer remoteAppender.Stop()

	// The storage has to be fully initialized before registering.
	if instrumentedStorage, ok := localStorage.(prometheus.Collector); ok {
		prometheus.MustRegister(instrumentedStorage)
	}
	prometheus.MustRegister(configSuccess)
	prometheus.MustRegister(configSuccessTime)

	// The notifier is a dependency of the rule manager. It has to be
	// started before and torn down afterwards.
	go notifier.Run()
	defer notifier.Stop()

	go ruleManager.Run()
	defer ruleManager.Stop()

	go targetManager.Run()
	defer targetManager.Stop()

	// Shutting down the query engine before the rule manager will cause pending queries
	// to be canceled and ensures a quick shutdown of the rule manager.
	defer cancelCtx()

	go webHandler.Run()

	// Wait for reload or termination signals.
	close(hupReady) // Unblock SIGHUP handler.

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)
	select {
	case <-term:
		log.Warn("Received SIGTERM, exiting gracefully...")
	case <-webHandler.Quit():
		log.Warn("Received termination request via web service, exiting gracefully...")
	case err := <-webHandler.ListenError():
		log.Errorln("Error starting web server, exiting gracefully:", err)
	}

	log.Info("See you next time!")
	return 0
}

// Reloadable things can change their internal state to match a new config
// and handle failure gracefully.
type Reloadable interface {
	ApplyConfig(*config.Config) error
}

func reloadConfig(filename string, rls ...Reloadable) (err error) { //filename such as /etc/prometheus.yaml
	log.Infof("Loading configuration file %s", filename)
	defer func() {
		if err == nil {
			configSuccess.Set(1)
			configSuccessTime.Set(float64(time.Now().Unix()))
		} else {
			configSuccess.Set(0)
		}
	}()

	conf, err := config.LoadFile(filename)
	if err != nil {
		return fmt.Errorf("couldn't load configuration (-config.file=%s): %v", filename, err)
	}

	// Add AlertmanagerConfigs for legacy Alertmanager URL flags.
	for us := range cfg.alertmanagerURLs {
		acfg, err := parseAlertmanagerURLToConfig(us)
		if err != nil {
			return err
		}
		conf.AlertingConfig.AlertmanagerConfigs = append(conf.AlertingConfig.AlertmanagerConfigs, acfg)
	}

	failed := false
	for _, rl := range rls {
		if err := rl.ApplyConfig(conf); err != nil {
			log.Error("Failed to apply configuration: ", err)
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("one or more errors occurred while applying the new configuration (-config.file=%s)", filename)
	}
	return nil
}
