//go:build desktop

package main

import (
	"context"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"

	"nfmonitor/internal/api"
	"nfmonitor/internal/netinfo"
	"nfmonitor/internal/priv"
)

func runDesktop() {
	pc := priv.NewClient()
	// Windows 等非 Linux 平台：只作为管理端监控远程 Linux 主机，不采集本机。
	srv := &api.Server{Priv: pc, Version: version, Mode: "desktop", NoLocal: !netinfo.LocalSupported}
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
