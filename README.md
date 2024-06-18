# OSV Ingester

It is a CLI tool that will connect to the OSV Google Cloud Storage Bucket [gcs://osv-vulnerabilities](https://storage.googleapis.com/osv-vulnerabilities/index.html) and fetch all the data to load it into a Redis Database.

This is part of the ONGuard service and is meant to be used as a CronJob to periodically synchronize OSV Data into
the ONGuard database.

## Packaging and running the application

The application can be packaged using:
```shell script
./mvnw package
```
It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

The application is now runnable using `java -jar target/quarkus-app/quarkus-run.jar`.

If you want to build an _über-jar_, execute the following command:
```shell script
./mvnw package -Dquarkus.package.type=uber-jar
```

The application, packaged as an _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

## Creating a native executable

You can create a native executable using: 
```shell script
./mvnw package -Pnative
```

Or, if you don't have GraalVM installed, you can run the native executable build in a container using: 
```shell script
./mvnw package -Pnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/onguard-<version>-runner`

If you want to learn more about building native executables, please consult https://quarkus.io/guides/maven-tooling.

## Running the application

By default it will load all the data:

```bash
./osv-ingester -Ddb.redis.host=my-redis -Ddb.redis.port=6379 gcs
```

But it is also possible to load a specific ecosystem:

```bash
./osv-ingester -Ddb.redis.host=my-redis -Ddb.redis.port=6379 gcs --ecosystem Maven
```