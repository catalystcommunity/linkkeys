package localrp

import (
	"strconv"
	"strings"
)

type identityInput struct {
	username string
	domain   string
}

func parseIdentityInput(value string) (identityInput, error) {
	value = strings.TrimSpace(value)
	if value == "" || !isASCII(value) || strings.Count(value, "@") > 1 {
		return identityInput{}, invalidIdentityInput()
	}
	username := ""
	domain := value
	if before, after, found := strings.Cut(value, "@"); found {
		if !validIdentityUsername(before) {
			return identityInput{}, invalidIdentityInput()
		}
		username, domain = before, after
	}
	if !validIdentityDomain(domain) {
		return identityInput{}, invalidIdentityInput()
	}
	return identityInput{username: username, domain: strings.ToLower(domain)}, nil
}

func invalidIdentityInput() error {
	return &InvalidInputError{Detail: "identity must be a username@domain or a domain"}
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 127 {
			return false
		}
	}
	return true
}

func validIdentityUsername(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '.' || value[len(value)-1] == '.' {
		return false
	}
	previousDot := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", rune(c))
		if !valid || c == '.' && previousDot {
			return false
		}
		previousDot = c == '.'
	}
	return true
}

func validIdentityDomain(value string) bool {
	if value == "" || len(value) > 259 {
		return false
	}
	host := value
	hasPort := false
	if strings.Contains(value, ":") {
		if strings.Count(value, ":") != 1 {
			return false
		}
		var portText string
		host, portText, _ = strings.Cut(value, ":")
		if portText == "" {
			return false
		}
		for i := 0; i < len(portText); i++ {
			if portText[i] < '0' || portText[i] > '9' {
				return false
			}
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		hasPort = true
	}
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") && !hasPort {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
