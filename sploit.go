package main

import (
	"fmt"
	auth "github.com/abbot/go-http-auth"
	flag "github.com/ogier/pflag"
	"github.com/op/go-logging"
	"github.com/snarlysodboxer/msfapi"
	"gopkg.in/fsnotify.v1"
	"gopkg.in/robfig/cron.v2"
	"gopkg.in/yaml.v2"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type config struct {
	MsfApiUri    string
	Username     string
	Password     string
	WatchDir     string
	ModulesFile  string
	ServeAddress string
}

type module struct {
	Type     string
	Name     string
	Options  map[string]interface{}
	CronSpec string
}

type host struct {
	Name     string
	Services []struct {
		Name  string
		Ports []int
	}
}

type service struct {
	Name    string
	Modules []module
}

type Daemon struct {
	Hosts         []host
	Services      []service
	API           *msfapi.API
	interruptChan chan os.Signal
	cron          cron.Cron
	waitGroup     sync.WaitGroup
	config        config
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
			log.Info("Closing....")
			daemon.cron.Stop()                                  // Stop the scheduler (does not stop any jobs already running).
			err := daemon.API.AuthTokenRemove(daemon.API.Token) // essentially logout
			if err != nil {
				log.Fatal(err)
			}
			log.Debug("Removed auth token %v", daemon.API.Token)
			daemon.waitGroup.Done()
			os.Exit(0)
		}
	}()
}

// read sploit.yml and set settings
func (daemon *Daemon) LoadSploitYaml(configFile string) {
	contents, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	config := config{}
	err = yaml.Unmarshal([]byte(contents), &config)
	if err != nil {
		log.Fatal(err)
	}
	daemon.config = config
	log.Info("Successfully loaded Sploit yaml file")
	log.Debug("Sploit config is %v", config)
}

// read modules.yml and map service names to Metasploit modules
func (daemon *Daemon) LoadModulesYaml() {
	contents, err := ioutil.ReadFile(daemon.config.ModulesFile)
	if err != nil {
		log.Fatal(err)
	}
	services := []service{}
	err = yaml.Unmarshal([]byte(contents), &services)
	if err != nil {
		log.Fatal(err)
	}
	daemon.Services = services // overwrite old
	log.Info("Successfully loaded modules yaml file")
	log.Debug("Modules config is: %v", services)
}

// read host.yml files from host.d into daemon.Hosts
func (daemon *Daemon) LoadHostYamls() {
	files, err := ioutil.ReadDir(fmt.Sprintf("./%s", daemon.config.WatchDir))
	if err != nil {
		log.Fatal(err)
	}
	hosts := []host{}
	for _, file := range files {
		if !file.IsDir() {
			regex := regexp.MustCompilePOSIX(".*.yml$")
			if regex.MatchString(file.Name()) {
				contents, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", daemon.config.WatchDir, file.Name()))
				if err != nil {
					log.Fatal(err)
				}
				host := host{}
				err = yaml.Unmarshal([]byte(contents), &host)
				if err != nil {
					log.Fatal(err)
				}
				hosts = append(hosts, host)
			}
		}
	}
	daemon.Hosts = hosts // overwrite old
	log.Info("Successfully loaded hosts yaml files")
	log.Debug("Host configs are: %v", hosts)
}

func (daemon *Daemon) SetupAPIToken() {
	tempToken, err := daemon.API.AuthLogin(daemon.config.Username, daemon.config.Password)
	if err != nil {
		log.Fatal(err)
	}
	daemon.API.Token = tempToken
	log.Debug("Got temp auth token: %v", tempToken)

	permToken := strings.Replace(tempToken, "TEMP", "PERM", -1)
	err = daemon.API.AuthTokenAdd(permToken)
	if err != nil {
		log.Fatal(err)
	}
	daemon.API.Token = permToken
	log.Debug("Set permanent auth token: %v", permToken)

	err = daemon.API.AuthTokenRemove(tempToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Removed temporary auth token: %v", tempToken)

	tokens, err := daemon.API.AuthTokenList()
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Current Token list: %v", tokens)
}

// create cron daemon
func (daemon *Daemon) CreateCronDaemon() {
	cron := cron.New()
	daemon.cron = *cron
}

// setup cron entries which send api calls to msfrpcd
func (daemon *Daemon) CreateCronEntries() {
	for _, daemonService := range daemon.Services {
		for _, module := range daemonService.Modules {
			log.Info("Creating a cron entry for: %v", module.Name)
			daemon.cron.AddFunc(module.CronSpec, func() { daemon.runModule(daemonService.Name, module) })
			daemon.waitGroup.Add(1)
		}
	}
}

// to be run by cron
func (daemon *Daemon) runModule(serviceName string, module module) {
	// TODO need mechanism to log and return immediately if cron is still running from last initiation
	for _, host := range daemon.Hosts {
		for _, hostService := range host.Services {
			if hostService.Name == serviceName {
				daemon.apiModuleExecuteAndWait(host.Name, hostService.Ports, module)
			}
		}
	}
}

func (daemon *Daemon) apiModuleExecuteAndWait(host string, ports []int, module module) {
	for _, port := range ports {
		options := make(map[string]interface{})
		for key, value := range module.Options {
			options[key] = value
		}
		options["RHOSTS"] = host
		options["RHOST"] = host
		options["RPORT"] = port
		jobID, err := daemon.API.ModuleExecute(module.Type, module.Name, options)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("Initiated '%s' to run against port '%d' on '%v' with job id %v.",
			module.Name, port, host, jobID)
		log.Debug("Module details: %v %v", module.Name, options)

		// TODO maybe don't loop forever? timeout?
		stillRunning := true
		for stillRunning {
			jobs, err := daemon.API.JobList()
			if err != nil {
				log.Error(err.Error())
			}
			log.Debug("The currently scheduled jobs are %v", jobs)
			if jobs[strconv.FormatInt(jobID, 10)] != "" {
				log.Debug("Job %v is still running, sleeping for 3 seconds", jobID)
				time.Sleep(3 * time.Second)
			} else {
				log.Info("Job %v is done", jobID)
				stillRunning = false
			}
		}
	}
}

// remove all cron daemon entries
func (daemon *Daemon) RemoveCronEntries() {
	entries := daemon.cron.Entries()
	for _, entry := range entries {
		log.Debug("Removing cron entry id %v", entry.ID)
		daemon.cron.Remove(entry.ID)
	}
}

// watch modules.yml file and host.d dir and recreate all cron entries upon changes
func (daemon *Daemon) CreateWatchers() {
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		defer watcher.Close()

		done := make(chan bool)
		timer := time.NewTimer(0 * time.Second)
		<-timer.C //empty the channel
		var event string

		go func() {
			for {
				select {
				case evnt := <-watcher.Events:
					timer.Reset(3 * time.Second)
					log.Debug("Reset timer for event: %v", evnt)
					event = evnt.Name
				case err := <-watcher.Errors:
					log.Fatalf("error:", err)
				}
			}
		}()

		go func() {
			for {
				select {
				case <-timer.C:
					log.Info("Reloading configuration after %v write", event)
					daemon.RemoveCronEntries()
					daemon.LoadModulesYaml()
					daemon.LoadHostYamls()
					daemon.CreateCronEntries()
				}
			}
		}()

		err = watcher.Add(daemon.config.WatchDir)
		if err != nil {
			log.Fatal(err)
		}
		err = watcher.Add(daemon.config.ModulesFile)
		if err != nil {
			log.Fatal(err)
		}
		<-done
	}()
}

// // start the msfprc daemon (serves the Metasploit API)
// func (daemon *Daemon) StartMsfRPCd() {
// }

// serve html
func (daemon *Daemon) CreateWebserver() {
	authenticator := daemon.loadDigestAuth("Sploit")
	http.HandleFunc("/", auth.JustCheck(&authenticator, daemon.rootHandler))
	go func() {
		http.ListenAndServe(daemon.config.ServeAddress, nil)
	}()
	log.Info("Started webserver on %v", daemon.config.ServeAddress)
}

func (daemon *Daemon) rootHandler(writer http.ResponseWriter, request *http.Request) {
	entries := daemon.cron.Entries()
	tmpl := template.Must(template.ParseFiles("root.html"))
	tmpl.Execute(writer, entries)
}

// // read database at regular intervals and send emails if needed
// func (daemon *Daemon) CreateNotifier() {
// }

// // update msf at regular intervals and search modules for keywords and send emails if needed
// func (daemon *Daemon) CreateUpdaterNotifier() {
// }

var log = logging.MustGetLogger("sploit")
var logFormat = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x} %{message}%{color:reset}",
)

func main() {
	// Logging
	logBackend := logging.NewLogBackend(os.Stderr, "", 0)
	logBackendFormatter := logging.NewBackendFormatter(logBackend, logFormat)
	logBackendLeveled := logging.AddModuleLevel(logBackendFormatter)
	//// Mechanism for debug logging
	if os.Getenv("DEBUG") == "true" {
		logBackendLeveled.SetLevel(logging.DEBUG, "sploit")
	} else {
		logBackendLeveled.SetLevel(logging.INFO, "sploit")
	}
	logging.SetBackend(logBackendLeveled)

	// Flags
	configFile := *flag.StringP("config-file", "c", "sploit.yml",
		"File to read Sploit settings.")
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		flag.PrintDefaults()
	}
	_, err := os.Stat(configFile)
	fileExists := !os.IsNotExist(err)
	flag.Parse()
	switch {
	case flag.NFlag() == 0:
		if !fileExists {
			flag.Usage()
			return
		}
	case flag.NFlag() == 1:
		if !fileExists {
			log.Fatalf("File %s not found!", configFile)
		}
	default:
		log.Fatal("Wrong number of arguements; 0 or 1.")
	}

	// Do it already
	daemon := &Daemon{}
	daemon.CreateWaitGroup()
	daemon.CreateInterruptChan()
	daemon.LoadSploitYaml(configFile)
	daemon.LoadModulesYaml()
	daemon.LoadHostYamls()
	daemon.API = msfapi.New(daemon.config.MsfApiUri)
	daemon.SetupAPIToken()
	daemon.CreateCronDaemon()
	// daemon.StartMsfRPCd()
	daemon.CreateCronEntries()
	daemon.cron.Start()
	daemon.CreateWatchers()
	daemon.CreateWebserver()
	// daemon.CreateNotifier()
	// daemon.CreateUpdaterNotifier()
	daemon.waitGroup.Wait() // Stay running until wg.Done() is called
}
