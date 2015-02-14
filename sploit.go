package main

import (
	"bytes"
	"database/sql"
	"fmt"
	auth "github.com/abbot/go-http-auth"
	_ "github.com/lib/pq"
	flag "github.com/ogier/pflag"
	"github.com/op/go-logging"
	"github.com/snarlysodboxer/msfapi"
	"gopkg.in/fsnotify.v1"
	"gopkg.in/robfig/cron.v2"
	"gopkg.in/yaml.v2"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type msfConfig struct {
	URI  string
	User string
	Pass string
}

type sploitConfig struct {
	WatchDir     string
	ModulesFile  string
	ServeAddress string
	UpdateSpec   string
	StatusSpec   string
	LogInfo      string
	LogDebug     string
}

type postgresConfig struct {
	DB   string
	User string
	Host string
	Port string
}

type smtpConfig struct {
	User string
	Pass string
	Host string
	From string
	To   string
}

type config struct {
	Sploit   sploitConfig
	MsfRpc   msfConfig
	Postgres postgresConfig
	SMTP     smtpConfig
}

type module struct {
	Name     string
	Commands []string
	CronSpec string
	Running  bool
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
	Services      *[]service
	API           *msfapi.API
	interruptChan chan os.Signal
	notifierChan  chan bool
	cron          cron.Cron
	internalCron  cron.Cron
	updateRunning bool
	lastUpdate    time.Time
	waitGroup     sync.WaitGroup
	cfg           config
	configFile    string
	db            sql.DB
	knownVulnIDs  []int
	knownModules  map[string][]string
	scanCount     int
	infoWriter    *os.File
	debugWriter   *os.File
}

type vulnerability struct {
	id         int
	CreatedAt  time.Time
	Address    string
	Name       string
	References string
}

func (daemon *Daemon) SetupLogging() {
	daemon.infoWriter = loadOrCreateFile(daemon.cfg.Sploit.LogInfo)
	var logFormatInfo = logging.MustStringFormatter(
		"%{color}%{time:15:04:05.000} %{level:.8s} pid:%{pid} %{message}%{color:reset}",
	)
	multiWriter := io.MultiWriter(os.Stderr, daemon.infoWriter)
	logBackendInfo := logging.NewLogBackend(multiWriter, "", 0)
	logBackendFormatterInfo := logging.NewBackendFormatter(logBackendInfo, logFormatInfo)
	logBackendLeveledInfo := logging.AddModuleLevel(logBackendFormatterInfo)
	if os.Getenv("DEBUG") == "true" {
		logBackendLeveledInfo.SetLevel(logging.DEBUG, "sploit")
	} else {
		logBackendLeveledInfo.SetLevel(logging.INFO, "sploit")
	}
	if daemon.cfg.Sploit.LogDebug != "" {
		daemon.debugWriter = loadOrCreateFile(daemon.cfg.Sploit.LogDebug)
		var logFormatDebug = logging.MustStringFormatter(
			"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x} %{message}%{color:reset}",
		)
		logBackendDebug := logging.NewLogBackend(daemon.debugWriter, "", 0)
		logBackendFormatterDebug := logging.NewBackendFormatter(logBackendDebug, logFormatDebug)
		logBackendLeveledDebug := logging.AddModuleLevel(logBackendFormatterDebug)
		logBackendLeveledDebug.SetLevel(logging.DEBUG, "sploit")
		logging.SetBackend(logBackendLeveledInfo, logBackendLeveledDebug)
	} else {
		logging.SetBackend(logBackendLeveledInfo)
	}
}

func (daemon *Daemon) LoadFlags() {
	daemon.configFile = *flag.StringP("config-file", "c", "sploit.yml",
		"File to read Sploit settings.")
	flag.Usage = func() {
		fmt.Printf("Usage:\n")
		flag.PrintDefaults()
	}
	_, err := os.Stat(daemon.configFile)
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
			log.Fatalf("File %s not found!", daemon.configFile)
		}
	default:
		log.Fatal("Wrong number of arguements; 0 or 1.")
	}
}

// supply a mechanism for stopping
func (daemon *Daemon) CreateInterruptChannel() {
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
			defer daemon.db.Close()
			defer daemon.infoWriter.Close()
			defer daemon.debugWriter.Close()
			daemon.waitGroup.Done()
			// os.Exit(0)
		}
	}()
}

// read sploit.yml and set settings
func (daemon *Daemon) LoadSploitYaml() {
	contents, err := ioutil.ReadFile(daemon.configFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg := config{}
	err = yaml.Unmarshal([]byte(contents), &cfg)
	if err != nil {
		log.Fatal(err)
	}
	daemon.cfg = cfg
	fmt.Println("Successfully loaded Sploit yaml file")
}

// read modules.yml and map service names to Metasploit modules
func (daemon *Daemon) LoadModulesYaml() {
	contents, err := ioutil.ReadFile(daemon.cfg.Sploit.ModulesFile)
	if err != nil {
		log.Fatal(err)
	}
	services := []service{}
	err = yaml.Unmarshal([]byte(contents), &services)
	if err != nil {
		log.Fatal(err)
	}
	daemon.Services = &services // overwrite old
	log.Info("Successfully loaded modules yaml file")
	log.Debug("Modules config is: %v", services)
}

// read host.yml files from host.d into daemon.Hosts
func (daemon *Daemon) LoadHostYamls() {
	files, err := ioutil.ReadDir(fmt.Sprintf("./%s", daemon.cfg.Sploit.WatchDir))
	if err != nil {
		log.Fatal(err)
	}
	hosts := []host{}
	for _, file := range files {
		if !file.IsDir() {
			regex := regexp.MustCompilePOSIX(".*.yml$")
			if regex.MatchString(file.Name()) {
				contents, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", daemon.cfg.Sploit.WatchDir, file.Name()))
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
	tempToken, err := daemon.API.AuthLogin(daemon.cfg.MsfRpc.User, daemon.cfg.MsfRpc.Pass)
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

func (daemon *Daemon) OpenDBConnection() {
	cfg := daemon.cfg.Postgres
	db, err := sql.Open("postgres",
		fmt.Sprintf("user=%s host=%s port=%s dbname=%s sslmode=disable",
			cfg.User, cfg.Host, cfg.Port, cfg.DB,
		),
	)
	if err != nil {
		log.Fatal(err)
	}
	daemon.db = *db
	log.Info("Successfully opened a database connection")
}

// setup cron entries which send api calls to msfrpcd
func (daemon *Daemon) CreateCronEntries() {
	for _, daemonService := range *daemon.Services {
		for _, module := range daemonService.Modules {
			log.Info("Creating a cron entry for: %v", module.Name)
			module.Running = false
			_, err := daemon.cron.AddFunc(module.CronSpec, func() {
				daemon.runModuleAgainstEachHostPort(daemonService.Name, &module)
			})
			if err != nil {
				log.Fatal(err)
			}
			daemon.waitGroup.Add(1)
		}
	}
}

// to be run by cron
func (daemon *Daemon) runModuleAgainstEachHostPort(serviceName string, module *module) {
	if module.Running {
		log.Warning("Module %v is already running, not running again.", module.Name)
		return
	} else {
		log.Info("Running cron entry for module %v", module.Name)
	}
	startTime := time.Now()
	log.Debug("%v start time", module.Name)
	module.Running = true
	for _, host := range daemon.Hosts {
		for _, hostService := range host.Services {
			if hostService.Name == serviceName {
				for _, port := range hostService.Ports {
					var commands []string
					for _, command := range module.Commands {
						cmd := strings.Replace(command, "SPLOITHOSTNAME", host.Name, -1)
						cmd = strings.Replace(cmd, "SPLOITHOSTPORT", strconv.Itoa(port), -1)
						cmd = fmt.Sprintf("%s\n", cmd)
						commands = append(commands, cmd)
					}

					log.Info("Initiating '%s' to run against port '%d' on '%v'.",
						module.Name, port, host.Name)
					log.Debug("Module details: %v", module)
					log.Debug("Commands that will be run:\n%#v", commands)
					_ = daemon.createConsoleAndRun(commands)
				}
			}
		}
	}
	log.Info("%v took %v to run", module.Name, time.Since(startTime))
	log.Debug("%v end time", module.Name)
	module.Running = false
	daemon.scanCount = daemon.scanCount + 1
	daemon.notifierChan <- true
}

func (daemon *Daemon) CreateNotifier() {
	daemon.notifierChan = make(chan bool, 10)
	go func() {
		for range daemon.notifierChan {
			daemon.recordAndNotify()
		}
	}()
}

// check for vulns in the database with an sql statement
func (daemon *Daemon) selectVulns() *[]vulnerability {
	query := strings.Join([]string{
		"SELECT vulns.id,vulns.created_at,hosts.address,vulns.name,array_agg(refs.name) AS references",
		"FROM vulns,hosts,vulns_refs,refs",
		"WHERE vulns.host_id = hosts.id AND refs.id = vulns_refs.ref_id AND vulns_refs.vuln_id = vulns.id",
		"GROUP BY vulns.id,vulns.created_at,hosts.address,vulns.name;",
	}, " ")
	vulns, err := daemon.db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer vulns.Close()
	vulnerabilities := []vulnerability{}
	for vulns.Next() {
		var vuln = vulnerability{}
		err = vulns.Scan(&vuln.id, &vuln.CreatedAt, &vuln.Address, &vuln.Name, &vuln.References)
		if err != nil {
			log.Fatal(err)
		}
		vuln.References = strings.Replace(vuln.References, ",", " ", -1)
		vuln.References = strings.Replace(vuln.References, "-http", " http", 1)
		log.Debug("Vulnerability found:\n%v %v %v %v",
			vuln.CreatedAt, vuln.Address, vuln.Name, vuln.References)
		vulnerabilities = append(vulnerabilities, vuln)
	}
	return &vulnerabilities
}

// record vulns database IDs and send emails when new vulns are found
func (daemon *Daemon) recordAndNotify() {
	vulns := daemon.selectVulns()
	for _, vuln := range *vulns {
		known := false
		for _, vulnID := range daemon.knownVulnIDs {
			if vulnID == vuln.id {
				known = true
			}
		}
		if known {
			log.Debug("Vulnerabilty %v is already known, not notifying", vuln.id)
		} else {
			var subject = fmt.Sprintf("New Vulnerability found on %s", vuln.Address)
			var message = fmt.Sprintf("Found the folowing Vulnerability on %s\n\n%s %s %s %s",
				vuln.Address, vuln.CreatedAt, vuln.Address, vuln.Name, vuln.References,
			)
			daemon.sendEmail(&subject, &message)
			daemon.knownVulnIDs = append(daemon.knownVulnIDs, vuln.id)
		}
	}
}

func (daemon *Daemon) sendEmail(subject, message *string) {
	const dateLayout = "Mon, 2 Jan 2006 15:04:05 -0700"
	body := "From: " + daemon.cfg.SMTP.From + "\r\nTo: " + daemon.cfg.SMTP.To +
		"\r\nSubject: " + *subject + "\r\nDate: " + time.Now().Format(dateLayout) +
		"\r\n\r\n" + *message
	domain, _, err := net.SplitHostPort(daemon.cfg.SMTP.Host)
	if err != nil {
		log.Fatalf("Error with net.SplitHostPort: %v", err)
	}
	auth := smtp.PlainAuth("", daemon.cfg.SMTP.User, daemon.cfg.SMTP.Pass, domain)
	err = smtp.SendMail(daemon.cfg.SMTP.Host, auth, daemon.cfg.SMTP.From,
		strings.Fields(daemon.cfg.SMTP.To), []byte(body))
	if err != nil {
		log.Fatalf("Error with smtp.SendMail: %v\n\n", err)
		log.Fatalf("Body: %v\n\n", body)
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

		err = watcher.Add(daemon.cfg.Sploit.WatchDir)
		if err != nil {
			log.Fatal(err)
		}
		err = watcher.Add(daemon.cfg.Sploit.ModulesFile)
		if err != nil {
			log.Fatal(err)
		}
		<-done
	}()
}

// serve html
func (daemon *Daemon) CreateWebserver() {
	authenticator := daemon.loadDigestAuth("Sploit")
	http.HandleFunc("/", auth.JustCheck(&authenticator, daemon.rootHandler))
	go func() {
		http.ListenAndServe(daemon.cfg.Sploit.ServeAddress, nil)
	}()
	log.Info("Started webserver on %v", daemon.cfg.Sploit.ServeAddress)
}

func (daemon *Daemon) rootHandler(writer http.ResponseWriter, request *http.Request) {
	var data struct {
		CronEntries []cron.Entry
		Vulns       []vulnerability
	}
	data.CronEntries = daemon.cron.Entries()
	data.Vulns = *daemon.selectVulns()
	tmpl := template.Must(template.ParseFiles("root.html"))
	tmpl.Execute(writer, &data)
}

// run separate cron daemon to update msf at regular intervals
func (daemon *Daemon) CreateUpdaterNotifier() {
	daemon.internalCron = *cron.New()
	daemon.updateRunning = false
	_, err := daemon.internalCron.AddFunc(daemon.cfg.Sploit.UpdateSpec, daemon.updateMsf)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Setup to git pull on this schedule '%v'", daemon.cfg.Sploit.UpdateSpec)
	daemon.internalCron.Start()
}

func (daemon *Daemon) updateMsf() {
	if daemon.updateRunning {
		log.Warning("An update of MSF is already running, not running again.")
		return
	}
	daemon.updateRunning = true
	log.Info("Beginning an update of MSF via Git.")

	commands := []string{
		"git pull",
	}
	responseData := daemon.createConsoleAndRun(commands)
	regex := regexp.MustCompilePOSIX("Already up-to-date")
	// skip the rest if git pull results in "Already up-to-date"
	if regex.MatchString(responseData) {
		log.Info("MSF is already up to date")
		daemon.updateRunning = false
		daemon.lastUpdate = time.Now()
		return
	}

	commands = []string{
		"reload_all",
	}
	_ = daemon.createConsoleAndRun(commands)

	// search modules for keywords, keep track of how many results there are, notify if it changes
	var buffer bytes.Buffer
	buffer.WriteString("search ")
	for _, service := range *daemon.Services {
		buffer.WriteString(fmt.Sprintf("%s ", service.Name))
	}
	commands = []string{
		buffer.String(),
	}
	responseData = daemon.createConsoleAndRun(commands)

	for _, service := range *daemon.Services {
		newModules := []string{}
		regex := regexp.MustCompilePOSIX(fmt.Sprintf("^.*%s*.*$", service.Name))
		lines := regex.FindAllString(responseData, -1)
		for _, line := range lines {
			exists := false
			for _, knownModule := range daemon.knownModules[service.Name] {
				if line == knownModule {
					exists = true
				}
			}
			if !exists {
				newModules = append(newModules, line)
			}
		}
		daemon.knownModules[service.Name] = lines
		if len(newModules) != 0 {
			var subject = fmt.Sprintf("New MSF modules matching '%s' found", service.Name)
			var message = fmt.Sprintf("After updating MSF, found the following new modules with '%s' in the name/description:\t\n%s",
				service.Name, strings.Join(newModules, "\n"),
			)
			daemon.sendEmail(&subject, &message)
		} else {
			log.Info("No new modules matching '%s' were found.", service.Name)
		}
	}

	daemon.updateRunning = false
	daemon.lastUpdate = time.Now()
}

// create console and run commands
func (daemon *Daemon) createConsoleAndRun(commands []string) (responseData string) {
	var buffer bytes.Buffer
	console, err := daemon.API.ConsoleCreate()
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("New console allocated: %v", console)

	_, err = daemon.API.ConsoleRead(console.ID)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Discarded console banner.")

	for _, command := range commands {
		command = fmt.Sprintf("%s\n", command)
		err = daemon.API.ConsoleWrite(console.ID, command)
		if err != nil {
			log.Fatal(err)
		}
		log.Debug("Wrote '%#v' to console %v", command, console.ID)
		// don't read too soon or you get blank response
		time.Sleep(750 * time.Millisecond)
		busy := true
		for busy {
			response, err := daemon.API.ConsoleRead(console.ID)
			if err != nil {
				log.Fatal(err)
			}
			log.Debug("Read console %v output:\n%v", console.ID, response.Data)
			buffer.WriteString(response.Data)
			if response.Busy {
				log.Debug("Console %v is still busy, sleeping 3 seconds..", console.ID)
				time.Sleep(3 * time.Second)
			} else {
				busy = false
			}
		}
	}

	err = daemon.API.ConsoleDestroy(console.ID)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Successfully removed console %v", console)
	return buffer.String()
}

// regular status/update email
func (daemon *Daemon) CreateStatusNotifier() {
	_, err := daemon.internalCron.AddFunc(daemon.cfg.Sploit.StatusSpec, daemon.sendStatusEmail)
	if err != nil {
		log.Fatal(err)
	}
}

func (daemon *Daemon) sendStatusEmail() {
	var subject = "MSF regular Status Update"
	var message bytes.Buffer
	// last successful MSF update
	when := "[An update has not yet been run]"
	if !daemon.lastUpdate.IsZero() {
		when = daemon.lastUpdate.String()
	}
	message.WriteString(fmt.Sprintf("Last successful MSF update: %v\n\n", when))
	// number of scans since last status email
	message.WriteString(fmt.Sprintf("%d scans have been run since the last email update\n\n", daemon.scanCount))
	// known vulns
	vulns := daemon.selectVulns()
	if len(*vulns) > 0 {
		message.WriteString("Currently know vulnerabilities: (Notifications have previously been sent.)\n\n")
		for _, vuln := range *vulns {
			str := fmt.Sprintf("\t%v %v %v %v\n", vuln.CreatedAt, vuln.Address, vuln.Name, vuln.References)
			message.WriteString(str)
		}
	} else {
		message.WriteString("No currently know vulnerabilities\n")
	}
	msg := message.String()
	daemon.sendEmail(&subject, &msg)
	daemon.scanCount = 0
	log.Debug("Sent Status Email")
}

func loadOrCreateFile(name string) *os.File {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		file, err := os.Create(name)
		if err != nil {
			log.Fatalf("Error with os.Create(): %v", err)
		}
		log.Debug("Created file %v", name)
		return file
	} else {
		file, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			log.Fatalf("Error with os.Open(): %v", err)
		}
		log.Debug("Opened existing file %v", name)
		return file
	}
}

var log = logging.MustGetLogger("sploit")

func main() {
	// TODO recover from most errors
	// TODO use a bash start.sh script to run postgres and msfrpcd in the same container
	// Do it already
	daemon := &Daemon{}
	daemon.knownModules = map[string][]string{}
	daemon.LoadFlags()
	daemon.LoadSploitYaml()
	daemon.SetupLogging()
	log.Info("Daemon starting up now")
	daemon.waitGroup = *new(sync.WaitGroup) // supply a mechanism for staying running
	daemon.CreateInterruptChannel()
	daemon.LoadModulesYaml()
	daemon.LoadHostYamls()
	daemon.OpenDBConnection()
	daemon.API = msfapi.New(daemon.cfg.MsfRpc.URI)
	daemon.SetupAPIToken()
	daemon.CreateNotifier()
	daemon.cron = *cron.New()
	daemon.CreateCronEntries()
	daemon.cron.Start()
	daemon.CreateWatchers()
	daemon.CreateWebserver()
	daemon.CreateUpdaterNotifier()
	daemon.CreateStatusNotifier()
	daemon.waitGroup.Wait() // Stay running until wg.Done() is called
}
