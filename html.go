// We import all of the needed assets here
package main

import _ "embed"

//go:embed html/login.html
var loginHTML string

//go:embed html/down.html
var downHTML string

//go:embed html/common.css
var commonCSS string

//go:embed html/mfa_new.html
var mfaNewHTML string

//go:embed html/mfa_validate.html
var mfaValidateHTML string
