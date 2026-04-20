# infra/docker_event_listener.py
"""
Docker Event Listener
Maintains ip_to_cgroup BPF map as containers start and stop.
Also pre-populates bigram_sketch_map with zeroed entries.

CRITICAL: The bigram CMS struct is 2072 bytes. Pre-populating from userspace
avoids the need to stack-allocate this struct in the BPF cold path
(which would exceed the 512-byte stack limit and get rejected by the verifier).

Runs as a daemon thread inside the loader process.
"""
import docker, subprocess, ctypes, json, time, logging
from pathlib import Path

log = logging.getLogger("causaltrace.docker")


class DockerEventListener:
    def __init__(self, bpf_obj):
        self.bpf = bpf_obj
        self.docker_client = docker.from_env()
        self.ip_to_cgroup = bpf_obj.get_table("ip_to_cgroup")
        self.bigram_sketch_map = bpf_obj.get_table("bigram_sketch_map")
        try:
            self.container_behavior = bpf_obj.get_table("container_behavior")
        except Exception:
            self.container_behavior = None
        self.known_containers = {}  # container_id → {ip, cgroup_id}
    
    def get_container_cgroup_id(self, container_id: str) -> int:
        """
        Get the cgroup_id for a running container.
        Method: inspect the container's init PID and read its cgroup id
        via /proc/<pid>/cgroup, then resolve via bpf_get_current_cgroup_id
        semantics (uses cgroupv2 inode number).
        """
        try:
            inspect = self.docker_client.api.inspect_container(container_id)
            pid = inspect['State']['Pid']
            if pid == 0:
                return None
            
            # Read cgroup id from /proc/<pid>/cgroup
            # For cgroupv2: single hierarchy, path in /sys/fs/cgroup
            cgroup_path_file = f"/proc/{pid}/cgroup"
            with open(cgroup_path_file) as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3 and parts[0] == '0':  # cgroupv2
                        cgroup_rel = parts[2].lstrip('/')
                        full_path = f"/sys/fs/cgroup/{cgroup_rel}"
                        # Get inode number (this is what bpf_get_current_cgroup_id returns)
                        stat = Path(full_path).stat()
                        return stat.st_ino
            return None
        except Exception as e:
            log.error(f"Failed to get cgroup_id for {container_id}: {e}")
            return None
    
    def get_container_ip(self, container_id: str) -> str:
        """Get the bridge network IP address of a container."""
        try:
            inspect = self.docker_client.api.inspect_container(container_id)
            networks = inspect['NetworkSettings']['Networks']
            for net_name, net_info in networks.items():
                ip = net_info.get('IPAddress', '')
                if ip:
                    return ip
            return None
        except Exception as e:
            log.error(f"Failed to get IP for {container_id}: {e}")
            return None
    
    def ip_to_int(self, ip_str: str) -> int:
        """Convert 'a.b.c.d' to 32-bit integer in network byte order."""
        parts = ip_str.split('.')
        val = (int(parts[0]) << 24 | int(parts[1]) << 16 |
               int(parts[2]) << 8 | int(parts[3]))
        # Network byte order (big-endian): swap bytes
        return (((val & 0xFF) << 24) | (((val >> 8) & 0xFF) << 16) |
                (((val >> 16) & 0xFF) << 8) | ((val >> 24) & 0xFF))
    
    def register_container(self, container_id: str):
        """Register a new container: update ip_to_cgroup + pre-populate bigram map."""
        ip = self.get_container_ip(container_id)
        cgroup_id = self.get_container_cgroup_id(container_id)
        
        if not ip or not cgroup_id:
            log.warning(f"Could not register container {container_id[:12]}: "
                       f"ip={ip}, cgroup_id={cgroup_id}")
            return
        
        # Update ip_to_cgroup map: ip_int → cgroup_id
        ip_int = self.ip_to_int(ip)
        self.ip_to_cgroup[ctypes.c_uint32(ip_int)] = ctypes.c_uint64(cgroup_id)
        
        # Pre-populate bigram_sketch_map with zeroed entry for this cgroup
        # This avoids the cold-path stack overflow in the dispatcher
        # The BPF struct must match struct bigram_sketch in causaltrace_common.h exactly
        # Using BCC's Python API to create a zeroed entry
        try:
            # Create a zeroed entry by accessing the map (BCC creates zero-value entry)
            leaf = self.bigram_sketch_map.Leaf()  # zero-initialized struct
            self.bigram_sketch_map[ctypes.c_uint64(cgroup_id)] = leaf
        except Exception as e:
            log.error(f"Failed to pre-populate bigram map for cgroup {cgroup_id}: {e}")

        # Pre-populate container_behavior map so behavior bits can be set by kernel
        # Without an existing entry, bpf_map_lookup_elem returns NULL and bits are never set
        if self.container_behavior is not None:
            try:
                leaf = self.container_behavior.Leaf()  # zero-initialized behavior_state
                self.container_behavior[ctypes.c_uint64(cgroup_id)] = leaf
            except Exception as e:
                log.error(f"Failed to pre-populate behavior map for cgroup {cgroup_id}: {e}")
        
        self.known_containers[container_id] = {
            'ip': ip,
            'cgroup_id': cgroup_id,
            'ip_int': ip_int
        }
        
        log.info(f"Registered container {container_id[:12]}: "
                f"ip={ip}, cgroup_id={cgroup_id}")
    
    def unregister_container(self, container_id: str):
        """Remove a stopped container's entries from BPF maps."""
        info = self.known_containers.pop(container_id, None)
        if not info:
            return
        
        try:
            del self.ip_to_cgroup[ctypes.c_uint32(info['ip_int'])]
        except Exception:
            pass
        
        try:
            del self.bigram_sketch_map[ctypes.c_uint64(info['cgroup_id'])]
        except Exception:
            pass
        
        log.info(f"Unregistered container {container_id[:12]}")
    
    def register_existing_containers(self):
        """Register all currently running containers at startup."""
        containers = self.docker_client.containers.list()
        for container in containers:
            self.register_container(container.id)
    
    def run(self):
        """Main event loop. Subscribe to Docker events and keep maps up to date."""
        log.info("Docker event listener starting...")
        self.register_existing_containers()
        
        # Subscribe to container start/stop events
        event_filters = {"type": "container", "event": ["start", "die", "stop"]}
        
        try:
            for event in self.docker_client.events(filters=event_filters, decode=True):
                event_type = event.get('Action', '')
                container_id = event.get('id', '')
                
                if event_type == 'start':
                    time.sleep(0.5)  # Wait for container to initialize PID/network
                    self.register_container(container_id)
                elif event_type in ('die', 'stop'):
                    self.unregister_container(container_id)
        except Exception as e:
            log.error(f"Docker event listener error: {e}")
