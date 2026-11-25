package main

import (
	"context"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"

	"nfmonitor/internal/api"
	"nfmonitor/internal/priv"
)

func runDesktop() {
	pc := priv.NewClient()
	srv := &api.Server{Priv: pc, Version: version}
	srv.Hosts, srv.HostsErr = openHosts()
	err := wails.Run(&options.App{
		Title:     "nfmonitor",
		Width:     1360,
		Height:    880,
		MinWidth:  960,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets:  assets,
			Handler: srv.Handler(), // 静态资源没命中的请求（/api/*）落到这里
		},
		BackgroundColour: &options.RGBA{R: 13, G: 13, B: 13, A: 1},
		OnShutdown: func(context.Context) {
			pc.Close()
			if srv.Hosts != nil {
				srv.Hosts.Close()
			}
		},
		Linux: &linux.Options{
			WebviewGpuPolicy: linux.WebviewGpuPolicyOnDemand,
			ProgramName:      "nfmonitor",
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
