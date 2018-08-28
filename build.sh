#!/bin/sh

go build -ldflags '-L /usr/local/ssl/lib -extldflags -Wl,-rpath=/usr/local/ssl/lib'
