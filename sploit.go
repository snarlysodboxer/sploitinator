package main

import (
	"fmt"
	"gopkg.in/robfig/cron.v2"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type service struct {
	name string
}

type servicePort struct {
	service *service
	port    int
}

type host struct {
	servicePorts []*servicePort
	entryIDs     []cron.EntryID
}

type module struct {
	name    string
	service *service
	options string
	spec    string
}

type Daemon struct {
	hosts         []*host
	modules       []*module
	interruptChan chan os.Signal
	cron          cron.Cron
	waitGroup     sync.WaitGroup
}

func NewDaemon() *Daemon {
	return &Daemon{}
}

// supply a mechanism for staying running
func (daemon *Daemon) CreateWaitGroup() {
	var wg sync.WaitGroup
	daemon.waitGroup = wg
}

// supply a mechanism for stopping
func (daemon *Daemon) CreateInterruptChan() {
	daemon.interruptChan = make(chan os.Signal, 1)
	signal.Notify(daemon.interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for _ = range daemon.interruptChan {
			fmt.Println("\nClosing....")
			daemon.cron.Stop() // Stop the scheduler (does not stop any jobs already running).
			defer daemon.waitGroup.Done()
			os.Exit(0)
		}
	}()
}

// create cron daemon
func (daemon *Daemon) CreateCron() {
	cron := cron.New()
	daemon.cron = *cron
}

// read each host.yml file from hosts.d and idempotently add/remove crons (each of which send api calls to msfrpcd)
func (daemon *Daemon) MatchCronsToHostFiles() {
	daemon.cron.AddFunc("@every 5s", func() { fmt.Println("Every five seconds") })
	daemon.waitGroup.Add(1)
}

// watch hosts.d dir and run daemon.MatchCronsToHostFiles() upon changes
func (daemon *Daemon) WatchHostsDotD() {
}

// serve html
func (daemon *Daemon) ServeHTML() {
}

// read database at regular intervals and send emails if needed
func (daemon *Daemon) Notify() {
}

func main() {
	daemon := NewDaemon()
	daemon.CreateWaitGroup()
	daemon.CreateInterruptChan()
	daemon.CreateCron()
	daemon.MatchCronsToHostFiles()
	daemon.WatchHostsDotD()
	daemon.cron.Start() // Actually start the cron daemon
	daemon.ServeHTML()
	daemon.Notify()
	daemon.waitGroup.Wait() // Stay running until wg.Done() is called
}
