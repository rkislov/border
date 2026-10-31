package backup

import "testing"

func TestNetworkMountRequiresRemoteFilesystem(t *testing.T) {
	for _, tc := range []struct {
		info string
		ok   bool
	}{
		{"20 1 0:1 / /mnt/backup rw - nfs4 192.0.2.1:/data rw", true},
		{"20 1 0:1 / /mnt/backup rw - cifs //server/share rw", true},
		{"20 1 0:1 / /mnt/backup rw - ext4 /dev/vda1 rw", false},
		{"20 1 0:1 / /mnt/backup ro - nfs4 server:/data ro", false},
		{"20 1 0:1 / /mnt/other rw - nfs4 server:/data rw", false},
		{"", false},
		{"20 1 0:1 / /mnt/backup rw - nfs4 server:/data rw\n21 20 0:2 / /mnt/backup/border rw - ext4 /dev/vda1 rw", false},
		{"20 1 0:1 / /mnt/backup rw - nfs4 server:/data rw\n21 20 0:1 /border /mnt/backup/border rw - nfs4 server:/data rw", true},
	} {
		if e := networkMountInfo(tc.info, "/mnt/backup", "/mnt/backup/border"); (e == nil) != tc.ok {
			t.Fatal(tc, e)
		}
	}
}
