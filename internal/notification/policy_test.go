package notification

import (
	"context"
	"fmt"
	"github.com/rkislov/border/internal/store"
	"testing"
	"time"
)

func TestPolicyDeliveryChannelIsolationAndSafeErrors(t *testing.T) {
	s := setup(t)
	ctx := t.Context()
	if e := s.Store.Exec(ctx, "INSERT INTO admins(username,password_hash,role,enabled) VALUES('alice','','admin',1)"); e != nil {
		t.Fatal(e)
	}
	for _, v := range []PolicyRecipient{{"email", "default", "admin@example.test", true}, {"sms", "default", "+79991234567", true}} {
		if e := s.SavePolicyRecipient(ctx, "alice", v); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().Unix()
	if e := s.Store.Exec(ctx, "INSERT INTO policy_notification_events(id,event_key,message,created_at) VALUES('event','event','test',?)", now); e != nil {
		t.Fatal(e)
	}
	for _, ch := range []string{"email", "sms"} {
		if e := s.Store.Exec(ctx, "INSERT INTO policy_notification_deliveries(id,event_id,target_id,target_revision,state,next_attempt,updated_at) VALUES(?,'event',?,1,'pending',?,?)", ch, "alice:"+ch, now, now); e != nil {
			t.Fatal(e)
		}
	}
	calls := map[string]int{}
	sender := func(ctx context.Context, j store.PolicyDeliveryJob) error {
		calls[j.Target.Channel]++
		if j.Target.Channel == "sms" {
			return fmt.Errorf("secret provider token must not be logged")
		}
		return nil
	}
	if e := s.DeliverPolicies(ctx, sender); e != nil {
		t.Fatal(e)
	}
	if calls["email"] != 1 || calls["sms"] != 1 {
		t.Fatal(calls)
	}
	ds, _ := s.Store.PolicyDeliveries(ctx)
	for _, d := range ds {
		if d.Channel == "email" && d.State != "sent" {
			t.Fatal(d)
		}
		if d.Channel == "sms" && (d.State != "pending" || d.LastError == "secret provider token must not be logged") {
			t.Fatal(d)
		}
	}
	if e := s.Store.Exec(ctx, "UPDATE policy_notification_deliveries SET next_attempt=0 WHERE state='pending'"); e != nil {
		t.Fatal(e)
	}
	if e := s.DeliverPolicies(ctx, sender); e != nil {
		t.Fatal(e)
	}
	if calls["email"] != 1 || calls["sms"] != 2 {
		t.Fatal(calls)
	}
}
func TestPolicyRecipientValidation(t *testing.T) {
	s := setup(t)
	ctx := t.Context()
	s.Store.Exec(ctx, "INSERT INTO admins(username,password_hash,role,enabled) VALUES('alice','','admin',1)")
	for _, v := range []PolicyRecipient{{"email", "default", "bad\nemail", true}, {"sms", "default", "123", true}, {"email", "unknown", "a@example.test", true}, {"push", "default", "https://evil.test", true}} {
		if e := s.SavePolicyRecipient(ctx, "alice", v); e == nil {
			t.Fatal(v)
		}
	}
}
