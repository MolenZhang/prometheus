/*
主要提供prometheus服务启动参数给其他函数使用
*/
package web

import (
	"github.com/prometheus/common/log"
)

type InitCfg struct {
	AlertManagerURL string
}

var ICfg InitCfg

func SetInitCfg(iCfg InitCfg) {
	ICfg.AlertManagerURL = iCfg.AlertManagerURL

	log.Infoln("成功保存启动参数:", ICfg)

}
func getInitCfg() InitCfg {
	return ICfg
}
