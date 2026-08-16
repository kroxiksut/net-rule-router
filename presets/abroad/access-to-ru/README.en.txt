Name: Access to RU from abroad
Category: abroad
Target country: RU
Where you are: outside Russia
Use case: Keep everything on the local provider, and reach Russian services through a secondary route that exits in Russia
Author: NetRuleRouter contributors
Tested on: Windows format validation baseline

Summary:
This pack is the mirror image of a domestic split. It suits people who live
outside Russia but still need Russian banking, government, marketplace, media
and work services that refuse foreign addresses.
- Primary route: empty on purpose. Everything not matched below goes out
  through the local provider, at full speed and with a local address.
- Secondary route: Russian zones (.ru, .su, .рф), Russian services that live on
  global domains, and Russian desktop applications.

Files:
- rules_primary.txt - header only, no rules. Import it to CLEAR the primary
  route; skip it if you want to keep your existing primary rules.
- rules_secondary.txt - the Russian side of the split.

Important notes:
- Foreign services are deliberately absent from the secondary list. Sending
  Google, streaming platforms, or European banking through a Russian exit
  invites captchas and account restrictions.
- Do not route a whole browser through the secondary route. Use domain rules:
  they have higher priority than application rules.
- Lines starting with "#" followed by a single value are DISABLED rules. They
  are shown in the GUI as toggled off; enable the ones you actually need.
- Review and adapt to your own provider and scenario. Service domains and
  process names change over time.
