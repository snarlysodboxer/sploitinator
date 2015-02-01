package main

import (
	"fmt"
	flag "github.com/ogier/pflag"
	// "gopkg.in/fsnotify.v1"
	"gopkg.in/robfig/cron.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
)

type module struct {
	Name        string
	Options     string
	PluralHosts bool
	CronSpec    string
}

type Daemon struct {
	Hosts []struct {
		Name     string
		Services []struct {
			Name  string
			Ports []int
		}
	}
	Services []struct {
		Name    string
		Modules []module
	}
	interruptChan chan os.Signal
	cron          cron.Cron
	waitGroup     sync.WaitGroup
	configDir     string
	modulesFile   string
}

// initialize a Daemon
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
			log.Println("\nClosing....")
			daemon.cron.Stop() // Stop the scheduler (does not stop any jobs already running).
			defer daemon.waitGroup.Done()
			os.Exit(0)
		}
	}()
}

// read modules.yml and map service names to Metasploit modules
func (daemon *Daemon) LoadModuleMappings() {
	contents, err := ioutil.ReadFile(daemon.modulesFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal([]byte(contents), daemon)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Loading mapped service names to Metasploit modules:\n%v",
		daemon.Services)
}

// watch modules.yml file and reload upon changes
func (daemon *Daemon) CreateModuleMappingsWatcher() {
}

// read host.yml files from host.d into daemon.Hosts
func (daemon *Daemon) LoadHostYamls() {
	files, err := ioutil.ReadDir(fmt.Sprintf("./%s", daemon.configDir))
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if !file.IsDir() {
			regex := regexp.MustCompilePOSIX(".*.yml$")
			if regex.MatchString(file.Name()) {
				contents, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", daemon.configDir, file.Name()))
				if err != nil {
					log.Fatal(err)
				}
				err = yaml.Unmarshal([]byte(contents), daemon)
				if err != nil {
					log.Fatal(err)
				}
				log.Printf("Loaded %v into daemon.HostConfigs", daemon.Hosts)
			}
		}
	}
}

// create cron daemon
func (daemon *Daemon) CreateCronDaemon() {
	cron := cron.New()
	daemon.cron = *cron
}

// setup cron entries which send api calls to msfrpcd
func (daemon *Daemon) CreateCronEntries() {
	for _, host := range daemon.Hosts {
		// for each host.service find the matching service-module mapping
		for _, hostService := range host.Services {
			for _, daemonService := range daemon.Services {
				if hostService.Name == daemonService.Name {
					log.Printf("'%s' '%d'\n", hostService.Name, hostService.Ports)
					for _, module := range daemonService.Modules {
						log.Printf("\t'%v'\n", module)
					}
				}
			}
		}
	}
	daemon.cron.AddFunc("@every 5s", func() { log.Println("Every five seconds") })
	daemon.waitGroup.Add(1)
}

// remove all cron daemon entries
func (daemon *Daemon) RemoveCronEntries() {
	entries := daemon.cron.Entries()
	for _, entry := range entries {
		daemon.cron.Remove(entry.ID)
	}
}

// watch host.d dir and reload the cron entries upon changes
func (daemon *Daemon) CreateHostDotDWatcher() {
	// daemon.RemoveCronEntries()
	// daemon.CreateCronEntries()
}

// start the msfprc daemon (serves the Metasploit API)
func (daemon *Daemon) StartMsfRPCd() {
}

// serve html
func (daemon *Daemon) CreateWebserver() {
}

// read database at regular intervals and send emails if needed
func (daemon *Daemon) CreateNotifier() {
}

func main() {
	daemon := NewDaemon()

	// Flags
	daemon.configDir = *flag.StringP("config-dir", "c", "host.d", "Directory to watch for config files.")
	daemon.modulesFile = *flag.StringP("modules-file", "m", "modules.yml", "File to read service-to-modules mapping.")
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	// TODO error properly if host.d directory doesn't exist
	// if flag.NFlag() != 1 {
	// 	flag.Usage()
	// 	return
	// }

	daemon.CreateWaitGroup()
	daemon.CreateInterruptChan()
	daemon.LoadModuleMappings()
	daemon.CreateModuleMappingsWatcher()
	daemon.LoadHostYamls()
	daemon.CreateCronDaemon()
	daemon.CreateCronEntries()
	daemon.CreateHostDotDWatcher()
	daemon.StartMsfRPCd() // TODO can we even do this?
	daemon.cron.Start()   // Actually start the cron daemon
	daemon.CreateWebserver()
	daemon.CreateNotifier()
	daemon.waitGroup.Wait() // Stay running until wg.Done() is called
}
