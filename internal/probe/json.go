// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import "encoding/json"

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
