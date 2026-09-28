# ROCKS Fleet architecture

This document describes the planned architecture of ROCKS Fleet without implying that unfinished components are already implemented.

## High-level design

The intended flow is:

Network
  ↓
Managed Switch SPAN / Port Mirroring
  ↓
ROCKS Edge
  ↓
Network metadata / flow features
  ↓
Structured telemetry
  ↓
ROCKS Hub
  ↓
Storage + Detection + ML
  ↓
Command Center / Dashboard

## Core responsibilities

### ROCKS Edge

ROCKS Edge is the observation layer. It is intended to handle network observation, extraction of metadata and flow features, local buffering, and sending structured telemetry to the Hub.

### ROCKS Hub

ROCKS Hub is the centralized analysis layer. It is intended to receive telemetry, store it, run detection logic, and host services that support the Command Center dashboard.

### Command Center

The Command Center is the administrator dashboard. It provides a safe operational interface to review detections and network posture without taking automated blocking actions.

## Metadata-first design

ROCKS is planned as a metadata-first system. It does not rely on packet payload storage. The design emphasis is on flow metadata, device behavior, and risk-oriented analysis rather than deep packet inspection.

## Deployment model

The project is designed to scale from a single Linux all-in-one deployment to a distributed deployment with multiple Edge sensors connected to one central Hub.

## Current status

Chunk 1 is only the foundation. Packet capture, ML, Hub services, and the Command Center are intentionally not implemented yet.
