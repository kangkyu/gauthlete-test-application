module test-application

go 1.22.7

replace github.com/kangkyu/gauthlete => ../gauthlete

require github.com/kangkyu/gauthlete v0.0.0-00010101000000-000000000000

require (
	github.com/alexedwards/scs/postgresstore v0.0.0-20240316134038-7e11d57e8885 // indirect
	github.com/alexedwards/scs/v2 v2.8.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	golang.org/x/crypto v0.28.0 // indirect
)
