package api

type AppRoleAuth struct {
	client *Client
}

// Token is used to return the client for token-backend API calls
func (a *Auth) AppRole() *AppRoleAuth {
	return &AppRoleAuth{client: a.c}
}

func (ar *AppRoleAuth) Role(role string) (*Secret, error) {
	request := ar.client.NewRequest("GET", "/v1/auth/approle/" + role)
	return ar.requestSecret(request)
}
func (ar *AppRoleAuth) Roles() (*Secret, error) {
	request := ar.client.NewRequest("LIST", "/v1/auth/approle")
	return ar.requestSecret(request)
}
func (ar *AppRoleAuth) Login(requestData *AppRoleLoginRequest) (*Secret, error) {
	request := ar.client.NewRequest("POST", "/v1/auth/approle/login")
	if err := request.SetJSONBody(requestData); err != nil {
		return nil, err
	}
	return ar.requestSecret(request);
}
func (ar *AppRoleAuth) Create(requestData *AppRoleRequest) error {
	request := ar.client.NewRequest("POST", "/v1/auth/approle")
	if err := request.SetJSONBody(requestData); err != nil {
		return err
	}
	response, err := ar.client.RawRequest(request)
	defer response.Body.Close()
	return err
}

func (ar *AppRoleAuth) Delete(role string) error {
	request := ar.client.NewRequest("DELETE", "/v1/auth/approle/" + role)
	response, err := ar.client.RawRequest(request)
	defer response.Body.Close()
	return err
}
func (ar *AppRoleAuth) RoleId(role string) (*Secret, error) {
	request := ar.client.NewRequest("GET", "/v1/auth/approle/role/" + role + "/role-id")
	return ar.requestSecret(request)
}
//Convenience method
func (ar *AppRoleAuth)Update(requestData *AppRoleRequest) error {
	return ar.Create(requestData)
}
func (ar *AppRoleAuth)UpdateRoleId(requestData *UpdateAppRoleIdRequest) error {
	request := ar.client.NewRequest("POST", "/v1/auth/approle/role/" + requestData.RoleName + "/role-id")
	if err := request.SetJSONBody(requestData); err != nil {
		return err
	}
	response, err := ar.client.RawRequest(request)
	defer response.Body.Close()
	return err
}

func (ar *AppRoleAuth)SecretId(role string) (*Secret, error) {
	request := ar.client.NewRequest("LIST", "/v1/auth/approle/" + role + "/secret-id")
	return ar.requestSecret(request)
}

func (ar *AppRoleAuth)UpdateSecretId(requestData *UpdateAppRoleSecretIdRequest) (*Secret, error) {
	request := ar.client.NewRequest("POST", "/v1/auth/approle/role" + requestData.RoleName + "secret-id")
	if err := request.SetJSONBody(requestData); err != nil {
		return nil, err
	}
	return ar.requestSecret(request)
}
func (ar *AppRoleAuth)LookupSecretId(requestData *AppRoleSecretIdRequest) (*Secret, error) {
	request := ar.client.NewRequest("POST", "/auth/approle/role/" + requestData.RoleName + "/secret-id/lookup")
	if err := request.SetJSONBody(requestData); err != nil {
		return nil, err
	}
	return ar.requestSecret(request)
}
func (ar *AppRoleAuth) DestroySecretId(requestData *AppRoleSecretIdRequest) error {
	request := ar.client.NewRequest("POST", "/auth/approle/role/" + requestData.RoleName + "/secret-id/destroy")
	if err := request.SetJSONBody(requestData); err != nil {
		return err
	}
	response, err := ar.client.RawRequest(request)
	defer response.Body.Close()
	return err
}
func (ar *AppRoleAuth) CustomSecretId(requestData *AppRoleCustomSecretIdRequest) (*Secret, error) {
	request := ar.client.NewRequest("POST", "/auth/approle/role/" + requestData.RoleName + "/custom-secret-id")
	if err := request.SetJSONBody(requestData);err != nil{
		return err
	}
	return ar.requestSecret(request)
}
func (ar *AppRoleAuth) requestSecret(request *Request) (*Secret, error) {
	response, err := ar.client.RawRequest(request)
	defer response.Body.Close()
	if (err != nil) {
		return nil, err
	}
	return ParseSecret(response.Body)
}

func NewAppRoleLoginRequest() *AppRoleLoginRequest {
	return &AppRoleLoginRequest{}
}
type AppRoleLoginRequest struct {
	RoleId   string `json:"role_id"`
	SecretId string `json:"secret_id,omitempty"`
}

func NewAppRoleRequest() *AppRoleRequest {
	return &AppRoleRequest{BindSecretId:true}
}

type AppRoleRequest struct {
	RoleName        string `json:"role_name"`
	BindSecretId    bool `json:"bind_secret_id,omitempty"`
	BoundCidrList   []string `json:"bound_cidr_list,omitempty"`
	Policies        []string `json:"policies,omitempty"`
	SecretIdNumUses int `json:"secret_id_num_uses,omitempty"`
	SecretIdTtl     int `json:"secret_id_ttl,omitempty"`
	TokenTtl        int `json:"token_ttl,omitempty"`
	TokenMaxTtl     int `json:"token_max_ttl,omitempty"`
	Period          int `json:"period,omitempty"`
}

func NewUpdateAppRoleIdRequest() *UpdateAppRoleIdRequest{
	return &UpdateAppRoleIdRequest{}
}
type UpdateAppRoleIdRequest struct {
	RoleName string `json:"role_name"`
	RoleId   string `json:"role_id"`
}

func NewUpdateAppRoleSecretIdRequest() *UpdateAppRoleSecretIdRequest  {
	return &UpdateAppRoleSecretIdRequest{}
}
type UpdateAppRoleSecretIdRequest struct {
	RoleName string `json:"role_name"`
	Metadata map[string]string `json:"metadata,omitempty"`
	CidrList string `json:"metadata,cidr_list"`
}

func NewAppRoleSecretIdRequest() *AppRoleSecretIdRequest{
	return &AppRoleSecretIdRequest{}
}
type AppRoleSecretIdRequest struct {
	RoleName string `json:"role_name"`
	SecretId string `json:"secret_id"`
}
func NewAppRoleCustomSecretIdRequest() *AppRoleCustomSecretIdRequest{
	return &AppRoleCustomSecretIdRequest{}
}
type AppRoleCustomSecretIdRequest struct {
	RoleName string `json:"role_name"`
	SecretId string `json:"secret_id"`
	Metadata map[string]string `json:"metadata,omitempty"`
	CidrList string `json:"cidr_list,omitempty"`
}