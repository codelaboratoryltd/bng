# Testing Checklist - Phase 1

Issues to verify before first `tilt up`:

## Tiltfile Issues

- [ ] **Context name verification**: k3d creates context as `k3d-bng`, verify `allow_k8s_contexts('k3d-bng')` is correct
- [ ] **Cluster already exists**: `local_resource` with `|| true` might not handle existing cluster correctly
  - Should we check if cluster exists first?
  - Or delete and recreate?
- [ ] **Helmfile timing**: Does helmfile-hydrate run before cluster is fully ready?
  - Might need better wait conditions
- [ ] **Resource dependencies**: Verify dependency chain:
  1. k3d-cluster
  2. k3d-wait (waits for nodes)
  3. helmfile-hydrate (generates charts)
  4. k8s_yaml (applies manifests)
  5. Cilium resources
  6. Hubble/Prometheus/Grafana

## Kustomization Issues

- [ ] **Missing chart directories**: `kustomization.yaml` references:
  - `../../charts/cilium`
  - `../../charts/prometheus`
  - `../../charts/grafana`

  These won't exist until helmfile-hydrate runs. Will kustomize fail?

  **Possible fix**: Run `cd charts && ./hydrate.sh` manually first?

## Helmfile Issues

- [ ] **Namespace creation**: Does `namespaces:` in kustomization.yaml work?
  - Might need to create `monitoring` namespace before applying Prometheus/Grafana
- [ ] **Cilium dependencies**: Prometheus scrape config references Cilium pods before they exist
  - Will Prometheus crash/restart until Cilium is ready?

## k3d Config Issues

- [ ] **Registry persistence**: `/tmp/k3d-bng-registry` - should this be a more permanent location?
- [ ] **DHCP port mapping**: Ports 6767/6768 - verify these don't conflict with anything
- [ ] **Node count**: 1 server + 2 agents - is this necessary for POC? Could we use just 1 server?

## Testing Order

Suggested first test:

```bash
# 1. Manually create cluster first
k3d cluster create -c clusters/bng-local/k3d-config.yaml

# 2. Verify context
kubectl config current-context
# Should be: k3d-bng

# 3. Run hydrate manually
cd charts
./hydrate.sh
cd ..

# 4. Check generated charts exist
ls -la charts/cilium
ls -la charts/prometheus
ls -la charts/grafana

# 5. Test kustomize build
kubectl kustomize clusters/bng-local

# 6. Then try Tilt
tilt up --context k3d-bng
```

## Known Issues to Fix

### Issue 1: Tilt creates cluster every time

**Problem**: `local_resource` with `|| true` will try to create cluster even if it exists.

**Fix options**:
1. Use `tilt args` to skip cluster creation: `tilt up --context k3d-bng -- --skip-cluster-create`
2. Check for cluster existence in script:
   ```bash
   k3d cluster list | grep -q '^bng' || k3d cluster create -c clusters/bng-local/k3d-config.yaml
   ```

### Issue 2: Helmfile runs before cluster ready

**Problem**: `resource_deps=['k3d-wait']` might not be enough.

**Fix**: Add explicit wait in helmfile-hydrate:
```bash
cmd='kubectl wait --for=condition=ready node --all --timeout=120s && cd charts && ./hydrate.sh'
```

### Issue 3: Kustomize fails on missing chart dirs

**Problem**: First run, charts/ dirs don't exist yet.

**Fix**: Either:
1. Commit generated charts to git (GitOps approach) ✅ YOU SAID THIS
2. Or change kustomization.yaml to be conditional

## Decisions Needed

1. **Commit rendered charts?** YES - you said we commit them for GitOps
2. **Manual or auto cluster creation?**
   - Auto (current Tiltfile) - convenient but error-prone
   - Manual (Makefile only) - more reliable
3. **Namespace creation strategy?**
   - In kustomization.yaml (current)
   - Separate manifest
   - Let Helm create them

## Next Steps After Testing

Once Phase 1 works:
1. Update TODO.md - mark Phase 1 complete
2. Document any gotchas in clusters/bng-local/README.md
3. Update CLAUDE.md with actual workflow
4. Move to Phase 2: eBPF development environment

---

**Note**: Don't test yet, we're noting issues for later. Move to Phase 2 first.
