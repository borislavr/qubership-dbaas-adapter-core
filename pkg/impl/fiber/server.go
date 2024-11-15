// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fiber

import (
	"context"
	"strconv"

	"github.com/Netcracker/qubership-dbaas-adapter-core/pkg/utils"
	"github.com/gofiber/fiber/v2"
)

func GetFiberServer(setUp func(app *fiber.App, ctx context.Context) error) (context.CancelFunc, *fiber.App, error) {
	serverCtx, cancel := context.WithCancel(context.Background())
	app := fiber.New(fiber.Config{Network: "tcp"})

	setupErr := setUp(app, serverCtx)

	return cancel, app, setupErr
}

func RunFiberServer(port int, setUp func(app *fiber.App, ctx context.Context) error) error {
	cancel, app, setupErr := GetFiberServer(setUp)
	if setupErr != nil {
		cancel()
		return setupErr
	}

	defer cancel()

	if utils.IsHttpsEnabled() {
		return app.ListenTLS(":"+strconv.Itoa(port), "/certs/tls.crt", "/certs/tls.key")
	} else {
		return app.Listen(":" + strconv.Itoa(port))
	}
}
