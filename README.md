# Inspex Slither Plugin

This is a collection of slither custom plugins developed by Inspex team. The plugins also come with utilities that should help the detection and reporting easier.

## Installation

### Integrate into Slither

The plugins are built from official Slither's plugin template. The installer will attempt to install the plugin into current python environment, which could have an error about the installer trying to write files without the permission. We strongly suggest you installing the plugins in a virtual environment. 

The official Slither's repository has already come with a virtual environment. You can use it to create a virtual environment solely for plugin-installed slither.

**Use Slither's env**
```bash
git clone https://github.com/crytic/slither.git
cd slither
make dev
source env/bin/activate
```

**Install the plugins**
```bash
cd inspex-plugins
python setup.py develop
```

### Docker

You can use `Dockerfile` to build a docker image for running slither with our plugins. 

```bash
# Create a new image from the Dockerfile file
docker build -t {image tag name} .

# Example
docker build -t inspexplugins .
```

When the image has been built, you can use the tag name that you've used to run a new container from the image. You can use the `-v` flag to let container to access file from the host. 

```bash
# Create a new container from the image
docker run -it -v {local path to be mounted}:/home/slither/mnt --name {new name of the container} {tag name of the image}

# Example
docker run -it -v ~/myDefiProject:/home/slither/mnt --name inspex-slither inspexplugins
```

If you have specified the name of the container, you can use that name to easily access to the container again by using the `docker exec` commmand.

```bash
# Access to the started container
docker exec -it {the container name} /bin/bash

# Example
docker exec -it inspex-slither /bin/bash
```

If the container has stopped, you can start it again by using the `docker start` command.
```bash
# Start the container
docker start -ia {the container name}

# Example
docker start -ia inspex-slither
```

## Usage

You can test the installed plugins by rurnning the `--list-detectors` or `--list-printers` flags to list the installed plugin. If the plugins have been installed successfully, we should see the new plugins in the result.

**List all registered detectors**
```bash
slither --list-detectors
```

![](https://s3-ap-northeast-1.amazonaws.com/inspex-hackmd-ee/uploads/upload_5508a23ba6db494d7961f68c591b5281.png)

**List all registered printers**
```bash
slither --list-printers
```

![](https://s3-ap-northeast-1.amazonaws.com/inspex-hackmd-ee/uploads/upload_8fe80b8d67d73664ac87fa96858e07ed.png)

If there is an error about the mismatch version of solidity. You can use `solc-select` to change the current version of solidity.

```bash
# you need to run the install first
solc-select install 0.8.17

# select the version by using the `use` sub-command 
solc-select use 0.8.17
```

## Detectors


- InsufficientLogging
    - `insufficient-logging`
    - Detect privilege functions that does not emit events 
- AssertStatement
    - `assert-statement`
    - Detect usage of `assert` statement in contracts
- FloatingPragmaVersion
    - `floating-pragma-version`
    - Detect usage of floating pragma version
- ModifiableOwnership
    - `modifiable-ownership`
    - Detect functions that can modify the contract ownership
- AssignMemoryArray
    - `assign-memory-array`
    - Detect the assigning of value into a memory array, which could be unintended
- InvokeUnknownExternalFunctions
    - `unknown-external-functions`
    - Detect an external call to user controllable addresses
- ApproveUnknownAddress
    - `approve-unknown-address`
    - Detect an approve to user controllable addresses
- StateChangingLoop
    - `state-changing-loop`
    - Detect loops that change states
- LoopReverted
    - `loop-reverted`
    - Detect loops that contain `require`, `assert`, or `revert` statements
- ExplicitTypeConversion
    - `explicit-type-conversion`
    - Detect an explicit type conversion, which could found a down-casting
- CentralizedState
    - `centralized-state`
    - Detect function that has access control that can change contract's states
- InexplicitVariableVisibility
    - `inexplicit-variable-visibility`
    - Detect states that does not explicitly decalre the visibility
- StrictEqualities
    - `strict-equalities`
    - Detect the usage of strict-equalities on a sensitive value, e.g., `balanceOf`.
- InspexExternalFunction
    - `inspex-external-function`
    - The overrided version of `external-function` for extending the printing function
- InspexIncorrectSolc
    - `inspex-solc-version`
    - The overrided version of `solc-version` for extending the printing function
- SelfInvocation
    - `this-usage`
    - Detect the usage of `this` to call itself
- LoopSkip
    - `loop-skip`
    - Detect loops that contains `return`, `break`, or `continue`.
- DirtyIterators
    - `dirty-iterators`
    - Detect loops the iterator can be modified in multiple places
- UnsafeInitiate
    - `unsafe-initiate`
    - Detect the `initialize()` function that does not safe 
- StandardTokenCheck
    - `common-standard-token`
    - Try guessing the standard that the contract trying to implement. If imple ment correctly, it should guess correctly.

## Printers

- InspexTestingGuideChecklist
    - `inspex-checklist`
    - Mapping the detector into our testing guide. And show the results according to the standard checklist.
    - Please noted that the printer does not use every detector on Slither. For the best result, please use the printer with the results from every detectors.
- InspexTestingGuideChecklistCSV
    - `inspex-checklist-csv`
    - Format the result from `inspex-checklist` into the CSV format.
- InspexTestingGuideChecklistXLS
    - `inspex-checklist-xls`
    - Format the result from `inspex-checklist-csv` into the xlxs format.