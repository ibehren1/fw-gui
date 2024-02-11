# To Do List

- [x] Create address groups/network groups/port groups.
- [x] Delete address groups/network groups/port groups.
- [x] Flash messages for actions.
- [x] Update delete rules to list the rules.
- [x] Filter Inbound/Outbound interfaces.
- [x] Live drop-downs for groups/hosts.
- [x] Download configuration commands.
- [x] Upload/download json data.
- [x] User and firewall name to *secure* the configs.
  - [x] Authentication of some form.
- [x] Implement stylesheets.
- [ ] Further implement stylesheets.
- [x] Add delete configuration option.
- [x] Display groups visually.
  - [ ] Make visual display of groups prettier.
- [x] Display chains visually.
- [x] Display filters visually.
  - [ ] Make visual display of filters prettier.

## Design

- [x] Update colors to make more readable
- [ ] Default fields/tabbing order in forms
  - [ ] Short-cuts / tooltips
- [x] & nbsp around bullets and radio buttons
- [ ] Alignment of fields on text forms

      Same with the textfields, I prefer to have a fixed aligned left border. Example at “Add table” and the name and description field who currently just gets “dumped” on the page without alignment. Having it aligned (as in the description text is like in its own column and all the white textfields is in its own column) makes it easier to read and less interrupting the read the whole page.

      Another option if you dont want to have two hidden columns for the description vs textfield is to align it vertically instead as you did over at “Add firewall group” where the field name is in orange (on darkgrey), textfield and then tooltip below it if needed. drawback with vertical alignment is that this is less compact than doing it two-column style.

- [x] Alignment of "choose file"
- [x] Page borders

## Suggested updates/features

- [ ] Email account validation

## Firewall functions

- [ ] Flowtables? --> Post 1.0.0 release.
- [x] Firewall group domain-group
- [x] Don't include empty fields like descriptions
- [x] Update all references of tables to chains.
- [ ] ~~Text editor for config?~~ --> Config is dynamicaly generated from JSON, no config to manually edit.

- [ ] ~~Look at options for working with official GUI project.~~ --> Not a goal at this time.  Using existing Napalm integration to push to firewall.

## Run Config on Firewall

- [x] Test running config command via Napalm
  - <https://docs.vyos.io/en/latest/automation/vyos-napalm.html>
  - [x] Additional updates around occasional timeouts.
  - [x] Ability to use SSH keys? encrypted
