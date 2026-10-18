/*
LINK - http://github.com/sipcapture/rtcagent

Copyright (C) 2023 QXIP B.V.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"rtcagent/hepclient"
)

// newHepClient builds a HEP client from the global flags. For the "tls"
// transport the server certificate is verified against the system trust store
// by default; an explicit CA bundle (--hep-tls-ca) and/or server name
// (--hep-tls-server-name) can be supplied for private deployments.
func newHepClient(gConf GlobalFlags) (*hepclient.HepClient, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if gConf.HepTLSCA != "" {
		pem, err := os.ReadFile(gConf.HepTLSCA)
		if err != nil {
			return nil, fmt.Errorf("read hep tls ca: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", gConf.HepTLSCA)
		}
		tlsConfig.RootCAs = pool
	}

	if gConf.HepTLSServerName != "" {
		tlsConfig.ServerName = gConf.HepTLSServerName
	}

	return hepclient.NewHepClient(
		gConf.HepServer,
		gConf.HepPort,
		gConf.HepTransport,
		hepclient.WithTLSConfig(tlsConfig),
	)
}
