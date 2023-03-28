package log_utils

import (
	log "github.com/sirupsen/logrus"
	"os"
)

func SetupLogger(logl string, logf string) {
	l, e := log.ParseLevel(logl)
	if e != nil {
		log.Fatalf("Unkonwn Log Level %s", logl)
	}
	log.SetLevel(l)

	if len(logf) <= 0 {
		log.SetOutput(os.Stdout)
	} else {
		f, err := os.OpenFile(logf, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Panic(err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Panic(err)
			}
		}()

		log.SetOutput(f)
	}
}
