sudo xdp-loader load -m skb enp0s3 xdp_drop_all.o &
sleep 60
sudo xdp-loader unload enp0s3 --all
