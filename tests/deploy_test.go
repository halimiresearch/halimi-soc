package tests

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The compose file is the shipped deployment path. A required variable that is
// absent from .env.example makes `docker compose up` fail before anything
// starts, and a volume mounted at the pre-18 path silently stores the database
// in an anonymous volume.
func TestDeployExampleCanStart(t *testing.T) {
	composeRaw, err := os.ReadFile("../deploy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	exampleRaw, err := os.ReadFile("../.env.example")
	if err != nil {
		t.Fatal(err)
	}

	var compose struct {
		Services map[string]struct {
			Image   string   `yaml:"image"`
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(composeRaw, &compose); err != nil {
		t.Fatalf("parse compose file: %v", err)
	}

	example := string(exampleRaw)
	for _, match := range regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*):\?`).FindAllStringSubmatch(string(composeRaw), -1) {
		name := match[1]
		if !regexp.MustCompile(`(?m)^` + name + `=`).MatchString(example) {
			t.Errorf("compose requires %s but .env.example does not define it", name)
		}
	}

	postgres, ok := compose.Services["postgres"]
	if !ok {
		t.Fatal("compose has no postgres service")
	}
	major := postgresMajor(t, postgres.Image)
	want := "/var/lib/postgresql"
	if major < 18 {
		want = "/var/lib/postgresql/data"
	}
	for _, mount := range postgres.Volumes {
		parts := strings.Split(mount, ":")
		if len(parts) == 2 && strings.HasPrefix(parts[0], "postgres-data") {
			if parts[1] != want {
				t.Fatalf("postgres %s data volume is mounted at %s, want %s (the image's PGDATA/VOLUME layout)",
					postgres.Image, parts[1], want)
			}
			return
		}
	}
	t.Fatalf("postgres %s has no named data volume: %v", postgres.Image, postgres.Volumes)
}

func postgresMajor(t *testing.T, image string) int {
	t.Helper()
	tag, ok := strings.CutPrefix(image, "postgres:")
	if !ok {
		t.Fatalf("unexpected postgres image %q", image)
	}
	digits := tag
	if i := strings.IndexAny(digits, ".-"); i >= 0 {
		digits = digits[:i]
	}
	major, err := strconv.Atoi(digits)
	if err != nil {
		t.Fatalf("parse postgres major from %q: %v", image, err)
	}
	return major
}
