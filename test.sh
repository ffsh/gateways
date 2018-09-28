#!/bin/bash
domains=('barnitz.freifunk-suedholstein.de' 'beste.freifunk-suedholstein.de' 'bille.freifunk-suedholstein.de' 'brunsbach.freifunk-suedholstein.de' 'heilsau.freifunk-suedholstein.de' 'hopfenbach.freifunk-suedholstein.de' 'krummbach.freifunk-suedholstein.de' 'piepenbek.freifunk-suedholstein.de' 'strusbek.freifunk-suedholstein.de' 'trave.freifunk-suedholstein.de' 'viehbach.freifunk-suedholstein.de')
for domain in ${domains[*]}
do
    echo "---"
    echo $domain
    dig +short $domain
done