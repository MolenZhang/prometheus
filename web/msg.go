package web

var PromReloadChan chan string

func init() {
	PromReloadChan = make(chan string)
}
