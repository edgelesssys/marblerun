# Graphene "Hello World!" sample
This sample shows how to run a [Graphene](https://github.com/oscarlab/graphene) application in Marblerun.

In essence, you have to add the `premain` process either by manually adding the Marblerun premain process as the entry point for your application (see: [`spawn`](spawn)), or by automatically injecting it as a preloaded shared library via Graphene's LD_PRELOAD feature (see: [`preload`](preload)).

`premain` will contact the Coordinator, set up the environment, and run the actual application. See the commented `hello.manifest.template` in the corresponding folder for details.

## Advantages / Disadvantages
`preload`:
* ✔ Faster application launch time
* ❌ argv arguments need to be provisioned during build time, ignoring the parameters set in the Marblerun manifest

`spawn`:
* ✔ argv can be defined in Marblerun's manifest.json
* ❌ Slower application launch time
