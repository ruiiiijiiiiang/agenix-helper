{
  hosts,
  nixosConfigurations ? { },
}:
assert builtins.isAttrs hosts;
assert builtins.isAttrs nixosConfigurations;
builtins.mapAttrs (
  hostname: host:
  let
    identityPaths =
      if host ? identityPaths then
        host.identityPaths
      else if host ? identity then
        [ host.identity ]
      else if builtins.hasAttr hostname nixosConfigurations then
        nixosConfigurations.${hostname}.config.age.identityPaths
          or (throw "Host '${hostname}' has no age.identityPaths in its NixOS configuration")
      else
        throw "Host '${hostname}' requires identityPaths, identity, or a matching nixosConfigurations entry";
  in
  if !builtins.isAttrs host then
    throw "Host '${hostname}' must be an attribute set"
  else if
    !builtins.isList identityPaths
    || identityPaths == [ ]
    || !builtins.all (path: builtins.isString path && path != "") identityPaths
  then
    throw "Host '${hostname}' identityPaths must be a nonempty list of path strings"
  else
    builtins.removeAttrs host [ "identity" ] // { inherit identityPaths; }
) hosts
