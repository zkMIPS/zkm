# ZKM

ZKM är en verifierbar generell datormiljö baserad på [Plonky2](https://github.com/0xPolygonZero/plonky2) och [MIPS mikroarkitekturen](https://en.wikipedia.org/wiki/MIPS_architecture), vilket gör att Ethereum kan bli det globala avvecklingsskiktet.

# Byggnad

För att bygga programmet kräver zkm en sen nattlig verktygskedja. Kör bara `cargo build --release` i zkm-katalogen.

# Kör exempel

Ett komplett exempel har presenterats i [exempel](./examples).

# Tips för externa bidragsgivare

Alla typer av externa bidrag är uppmuntrade och välkomna!

## Allmänna tips för dina pull requests

* PR rättar till en bugg
I PR-beskrivningen, beskriv tydligt men kortfattat buggen, inklusive hur den kan reproduceras, fel/undantag som uppstod och hur din PR rättar till buggen.

* PR implementerar en ny funktion

I PR-beskrivningen, beskriv tydligt men kortfattat

> 1. vad funktionen används till
> 2. vilken metod som används för att implementera den
> 3. Alla PR:er för nya funktioner måste inkludera lämpliga testsviter.

* PR förbättrar prestandan

För att hjälpa till att filtrera bort falska positiva måste PR-beskrivningen för en prestandaförbättring tydligt identifiera

> 1. den målsatta prestandaflaskan (en per PR för att undvika förvirring!)
> 2. hur prestandan mäts
> 3. egenskaper hos den använda maskinen (CPU, OS, #trådar om lämpligt) prestanda före och efter PR:en

# Licenser

ZKM distribueras enligt villkoren i [MIT-licensen](https://opensource.org/licenses/MIT).

# Säkerhet

Denna kod har ännu inte granskats och bör inte användas i något produktionsystem.

