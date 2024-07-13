package domain

type UserInfo struct {
	Sub string `json:"sub"`

	Profile
	Address *Address `json:"address,omitempty"`
	Email
	Phone

	Extra map[string]any `json:"-"`
}

type Profile struct {
	// profile claims
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	NickName          string `json:"nickname,omitempty"`
	PrefferedUsername string `json:"preferred_username,omitempty"`
	Gender            string `json:"gender,omitempty"`
	BirthDate         string `json:"birthdate,omitempty"`
	Profile           string `json:"profile,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Website           string `json:"website,omitempty"`
	ZoneInfo          string `json:"zoneinfo,omitempty"`
	Locale            string `json:"locale,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
}

type Address struct {
	// address claim
	Formatted string `json:"formatted,omitempty"`
	Street    string `json:"street_address,omitempty"`
	Locality  string `json:"locality,omitempty"`
	Region    string `json:"region,omitempty"`
	Postal    string `json:"postal_code,omitempty"`
	Country   string `json:"country,omitempty"`
}

type Email struct {
	// email claim
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

type Phone struct {
	// phone_number claim
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool  `json:"phone_number_verified,omitempty"`
}
