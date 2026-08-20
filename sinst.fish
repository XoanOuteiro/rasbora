function sinst --description "apt update, then install -y"
    if test (count $argv) -eq 0
        echo "usage: sinst PACKAGE..."
        return 1
    end
    sudo apt update && sudo apt install -y $argv
end
