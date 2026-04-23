def build_port_args(ports_spec, esxi_ports):
    if not ports_spec or ports_spec.lower() == "none":
        ports_spec = ""

    # If top-X is requested, we convert it
    if ports_spec.startswith("top-"):
        num = ports_spec.split("-")[1]
        if esxi_ports:
            return ["-p", esxi_ports, "--top-ports", num]
        else:
            return ["--top-ports", num]
    else:
        # Static port list
        if esxi_ports and ports_spec:
            combined = f"{esxi_ports},{ports_spec}"
        elif esxi_ports:
            combined = esxi_ports
        else:
            combined = ports_spec
            
        if combined:
            return ["-p", combined]
        return []

print(build_port_args("top-1000", "80,443,902"))
print(build_port_args("8080,9090", "80,443,902"))
print(build_port_args("top-100", ""))
