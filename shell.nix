{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  packages = with pkgs; [
    # Shell stuff
    fish
    starship

    gcc
    gnumake
    clang-tools

    inotify-tools
  ];
  shellHook = ''
    exec ${pkgs.fish}/bin/fish -C "starship init fish | source"
  '';
}
