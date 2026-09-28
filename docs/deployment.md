# Deployment

This project is designed around a future Linux-first deployment model with both single-machine and distributed configurations.

## All-in-one deployment

The eventual system is intended to support an all-in-one deployment in which:

- ROCKS Edge runs on one Linux machine
- ROCKS Hub runs on the same machine
- the database lives locally
- detection logic runs locally
- the dashboard is served from the same system

This model is useful for small deployments, lab environments, or low-cost monitoring setups.

## Distributed deployment

The eventual system is intended to support distributed deployments where:

- multiple Edge sensors are deployed at remote network observation points
- each Edge sensor forwards telemetry to a central self-hosted Hub
- the Hub stores telemetry and runs detection logic
- the Command Center dashboard connects to the Hub for centralized monitoring

This is the intended architecture for larger environments and multiple network segments.

## Important constraints

- The project must support managed switch SPAN or port mirroring
- Network observation must not assume that attaching a machine directly to a switch provides every packet
- The system remains metadata-first and does not store payloads
- Detection remains informational and never automatically blocks or attacks devices
