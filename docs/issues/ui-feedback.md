# UI feedback: compare, staging and review

Feedback from using the Compare view, collected 2026-11-18. Each item has what was reported, then what was done about it.

## 1. Certificate expiry scan times out

> Timeouts on certificate expiry: "Unexpected token '<' is not valid JSON"

A large scan ran as a single long request. A reverse proxy in front of Lockstep (an ingress or router) gave up first and returned its own HTML error page. The browser then tried to parse that page as JSON.

- [x] The scan now streams its progress as NDJSON (`POST /api/expiry/stream`). Proxies see data arriving, so their read timeouts don't trigger, and the page shows how far the scan has got. `POST /api/expiry` still returns the whole result in one response.
- [x] An HTML or other non-JSON error from a proxy now produces a readable message, such as "The server didn't answer in time (HTTP 504 from a proxy)…", instead of a JSON parse error.

## 2. "All keys to right" doesn't light up when every key is picked one by one

- [x] A secret counts as fully staged when every key that can be copied in that direction is staged, whether that was done with the button or key by key. The button then shows as pressed, and clicking it unstages them all.

## 3. Group secrets by path

- [x] Results have a **Group** control with three settings: *None*, *Folder* and *Staged*. *Folder* puts secrets under a header for each parent path, and each group can be collapsed.

## 4. Move every secret under a path in one go

- [x] Each folder header has **← all to left** and **all to right →** buttons, which stage every secret in that folder. Without grouping, the same buttons act on everything shown, so you can type a path into the filter and move all of it.

## 5. Override right should start from the left's value

- [x] When you edit a value on one side, the field starts with the other side's value if that side has the key. Otherwise it starts with the side's own current value. With *Show values* off, values aren't fetched, so the field starts empty.

## 6. Override opens a separate panel instead of using the value fields

- [x] Overrides are edited in place: each value has **Edit**, which turns that value into a text field. The separate override panel is gone. **＋ Add key** adds a new key to one side or both.

## 7. Can't remove things in the review

- [x] Each key in the review has a **×** that unstages it, and each secret has **Remove**. The preview then updates.

## 8. Can't save a plan when overrides are set

- [x] A plan can now hold typed values. Only override values go in: copied values are still read from the source when the plan is applied. Before saving, the review warns that the file will contain those values in plain text. The plan report lists the names of typed keys but never their values.

## 9. Expand all / collapse all, group by staged

- [x] **Expand all** and **Collapse all** act on the secrets shown. **Group: Staged** lists staged secrets first, under their own header.

## 10. Delete a key

- [x] Each value has a **Delete** button, which stages removing that key from that side. Each key also has **Delete everywhere**, which removes it from every side that has it. Removals appear in the review as *remove*, and work in plans too. A removal writes a new version without the key, so older versions still have it.

## 11. A staged override hides its new value

> The new value is hidden in the panel, while the row still says "left only", shows the orange "set" arrow and a dashed "not present" box.

- [x] A staged value now replaces what the row shows on that side: the new value, marked *new value*, with **Edit** and **Undo**. A key you've added gets its own row.
