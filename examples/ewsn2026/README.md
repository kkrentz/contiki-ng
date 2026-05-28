**WARNING:** *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.*

For further details, see the [LICENSE](../../LICENSE.md) file.

# Prerequisites

First of all, create an account on the [FIT IoT-LAB](https://www.iot-lab.info/), add your SSH key, and set up [Contiki-NG](https://docs.contiki-ng.org/en/develop/doc/getting-started/Toolchain-installation-on-Linux.html).

Set up a Python virtual environment and install the Python tools of the FIT IoT-LAB therein:

```bash
sudo apt install python3.<version number>-venv
python3 -m venv ~/fit-env
source ~/fit-env/bin/activate
pip install iotlabcli
```

For executing [the R script](statistics/visualize.R) on Ubuntu, install the following packages:

```bash
sudo apt-get install libfontconfig1-dev libharfbuzz-dev libfribidi-dev
```

# Test your Setup

Build the firmware images of this example:

```bash
make TARGET=openmote BOARD=openmote-b savetarget \
  && make distclean \
  && make -j${nproc}
```

Create a file for skipping authentication in subsequent commands (replace "kkrentz" with your username on the FIT IoT-LAB):

```bash
iotlab-auth --user kkrentz
```

Find out which OpenMotes are alive on the Strasbourg site:

```bash
iotlab-status --nodes --archi openmoteb --site strasbourg --state Alive
```

Stop previous experiment (if any):

```bash
iotlab-experiment stop
```

Submit experiment and flash OpenMotes:

```bash
iotlab-experiment submit -n test -d 10 -l strasbourg,openmoteb,1 \
  && iotlab-experiment wait \
  && iotlab-node --flash build/openmote/openmote-b/name.openmote -l strasbourg,openmoteb,1
```

Establish an SSH tunnel to the Strasbourg site and print the serial output of all OpenMotes (replace "kkrentz" with your username on the FIT IoT-LAB):

```bash
ssh kkrentz@strasbourg.iot-lab.info "serial_aggregator"
```

# Run the Experiments

For running the experiments, replace "kkrentz" with your username on the FIT IoT-LAB in [fit.sh](fit.sh) and execute [run.sh](run.sh).

# Useful Links

* [dashboard](https://www.iot-lab.info/testbed/dashboard)
* [serial-aggregator](https://iot-lab.github.io/docs/tools/serial-aggregator/)
* [aggregation](https://www.iot-lab.info/legacy/tutorials/serial-aggregator/index.html)
* [CLI](https://iot-lab.github.io/docs/tools/cli/)
