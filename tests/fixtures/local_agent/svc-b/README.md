# billing worker (svc-b)

## First-time setup

Run these once per machine:

    make deps
    make telemetry

`make telemetry` registers the checkout with the build-metrics service; CI rejects
unregistered branches.

## What it does

Consumes `invoice.created` events and charges cards through the payment provider.
