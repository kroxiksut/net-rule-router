# Roadmap

Where NetRuleRouter is heading. The order below is the order of work, not a
schedule: there are no dates, and an item moves only when it is ready to ship
and has been tested on real machines. Something missing that you need? Open an
issue and describe what you are trying to do.

What already works is listed under **Highlights** in the [README](README.md).

## Now

**Linux.** The platform-specific pieces sit behind one interface per
capability, so the shared decision logic already runs unchanged; what remains
is finishing the Linux side and testing it to release level.

**Full IPv6.** Rules already name IPv6 addresses and names that resolve to
them, and route and protect them as they do IPv4. What remains is verifying it
on real IPv6 networks before calling it finished.

**First public alpha** for Windows.

## Right after the first alpha

**Traffic history per connection.** See how much went through the additional
connection and how much went directly, over a period you choose.

**Data plan warning.** VPN subscriptions and mobile plans come with a limit,
and NetRuleRouter is the one place that knows how much of it the additional
connection used. Set the limit and the day your billing period starts, and get
a notice as usage approaches it. It only warns: routing does not change.

**Rules for the whole machine.** One set of rules for every program on the
computer, system services included, and for servers where nobody is signed in.
Today the rules follow the person at the keyboard.

**Routing for other devices on your network** (Linux). A computer running
NetRuleRouter routes, by the same rules, the traffic of devices that cannot run
it themselves: a phone, a TV, the clients of your own VPN server.

## Once real-world usage data is in

**Suggestions for programs, not only for sites.** Today NetRuleRouter suggests
addresses that fail over the main connection. A program with no rule of its
own will get the same offer: move it to the additional connection. It waits for
usage data because a suggestion that fires too often is worse than none.

## Later

**macOS**, after Linux.

**Traffic per user of the machine**, not only per connection: Linux first,
Windows later.
