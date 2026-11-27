<!-- Chart spacing: GitHub strips blank-line tricks (<br>, &nbsp;), so every chart SVG carries 160px of white padding at the bottom (extra height in both viewBox and the background rect). Add the same padding to any new chart. -->

In this repository:

- the Forge app is [`apps/forge`](../../apps/forge);
- the remote service is [`apps/remote`](../../apps/remote); and
- the remote agent is played by the scenario simulator in [`apps/scenarios`](../../apps/scenarios).

![Remote agents in Jira](remote-agent-terminology.svg)

---

![Handling Jira tasks: the two kinds of request](jira-requests.svg)

---

![Data shared with your remote agent](invocation-payload.svg)

---

The scenario is defined in [`apps/scenarios/demo-default.yaml`](../../apps/scenarios/demo-default.yaml).

![Walkthrough: the demo-default scenario](demo-default-scenario.svg)

---

The scenario is defined in [`apps/scenarios/demo-long-running.yaml`](../../apps/scenarios/demo-long-running.yaml).

![Walkthrough: the demo-long-running scenario](demo-long-running-scenario.svg)

---

The scenario is defined in [`apps/scenarios/demo-jira.yaml`](../../apps/scenarios/demo-jira.yaml).

![Walkthrough: the demo-jira scenario](demo-jira-scenario.svg)

---

The scenario is defined in [`apps/scenarios/demo-jira.yaml`](../../apps/scenarios/demo-jira.yaml), with the `transition` step set to `real: true`.

![Walkthrough: the demo-jira scenario, with a real transition](demo-jira-transition-scenario.svg)

---

The scenario is defined in [`apps/scenarios/input-resume.yaml`](../../apps/scenarios/input-resume.yaml).

![Walkthrough: the input-resume scenario](demo-input-resume-scenario.svg)
