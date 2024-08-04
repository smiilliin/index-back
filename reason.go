package main

type StatusResponse struct {
	Status bool   `json:"status"`
	Reason string `json:"reason"`
}

const ReasonJSONParse = "JSON_PARSE"
const ReasonIDInvalid = "ID_INVALID"
const ReasonPasswordInvalid = "PASSWORD_INVALID"
const ReasonRecaptchaFailed = "RECAPTCHA_FAILED"
const ReasonIDUsing = "ID_USING"
const ReasonInputIncorrect = "INPUT_INCORRECT"
const ReasonUnknown = "UNKNOWN"
const ReasonNotiong = "NOTHING"
const ReasonRefreshInvalid = "REFRESH_TOKEN_INVALID"
const ReasonAccessInvalid = "ACCESS_TOKEN_INVALID"
