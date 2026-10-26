package directory

import "testing"

func TestLDAPConfig(t *testing.T) {
	for _, name := range []string{"BORDER_LDAP_URL", "BORDER_LDAP_BASE_DN", "BORDER_LDAP_BIND_DN", "BORDER_LDAP_BIND_PASSWORD", "BORDER_LDAP_USER_ATTRIBUTE", "BORDER_LDAP_CA"} {
		t.Setenv(name, "")
	}
	if l, err := FromEnv(); err != nil || l != nil {
		t.Fatal("disabled config")
	}
	t.Setenv("BORDER_LDAP_URL", "http://directory.example.test")
	if _, err := FromEnv(); err == nil {
		t.Fatal("insecure scheme accepted")
	}
	t.Setenv("BORDER_LDAP_URL", "ldaps://directory.example.test:636")
	if _, err := FromEnv(); err == nil {
		t.Fatal("anonymous search accepted")
	}
	t.Setenv("BORDER_LDAP_BASE_DN", "dc=example,dc=test")
	t.Setenv("BORDER_LDAP_BIND_DN", "cn=reader,dc=example,dc=test")
	t.Setenv("BORDER_LDAP_BIND_PASSWORD", "test-only-password")
	for _, attribute := range []string{"sAMAccountName", "uid", "userPrincipalName"} {
		t.Setenv("BORDER_LDAP_USER_ATTRIBUTE", attribute)
		l, err := FromEnv()
		if err != nil || l.TLS.InsecureSkipVerify || l.UserAttribute != attribute {
			t.Fatal("LDAP config", err)
		}
	}
	t.Setenv("BORDER_LDAP_USER_ATTRIBUTE", "uid)(objectClass=*")
	if _, err := FromEnv(); err == nil {
		t.Fatal("filter injection in attribute accepted")
	}
}
