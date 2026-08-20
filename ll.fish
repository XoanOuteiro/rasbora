function ll --wraps='lsd -lh --group-dirs first' --description 'alias ll lsd -lh --group-dirs first'
    lsd -lh --group-dirs first $argv
end
