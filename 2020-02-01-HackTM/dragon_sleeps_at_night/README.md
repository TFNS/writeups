# The dragon sleeps at night (misc, 50p, 332 solved)

A rather easy misc challenge.
We get to play a game:

```
Welcome to our little town!
We're glad you've decided to help us fight the dragon and bring back this town to it's old glory.

We have a shop where you can buy many different weapons for your fight!
There's also a mine for you to work at. The boss is a very trusting guy, don't try to scam him please.

-------------------------------
-------------------------------
Day: 0
Time: 00:00
Your balance: $0
-------------------------------
1: Go to store
2: Go to work
3: Go to dragons cave
4: Go home
5: Storage
```

If we go to work, we can earn money to buy a sword in the store.
First trick is that we can specify how long we worked.
The value can be only 3 digits long, but it allows for scientific notation, and we can se `9e9` to get lots of money.

With that we can buy sword lvl 5 from store.

However, this sword doesn't kill the dragon!
On a sidenote, the dragon instantly kills us unless we approach him at midnight, so we need to send some empty instructions to let the time pass.

There are 2 last places we can use -> storage and home.

When you place something in storage it says:
`Please note: Swords degrade by 1 level for each day they are left in storage.`

Now the trick is that when we're resting at home, we can say how long we want to rest, and there is no check for negative values.
This means we can rest for `-1` days and behold:
```
Storage contains a sword level 6
Do you want to take the sword out? (y/n) > Receiving level 6 sword.
```

With this sword we can go (at midnight!) to the dragon:

```
Welcome to the dragon's cave
-------------------------------
You see the dragon sleeping next to a pile of bodies.
They look disturbingly fresh.
Carrying your level 6 sword, you walk over to the dragon
You're still dizzy from the time travelling
About half way towards the dragon, the blade starts vibrating
As if by magic, it's pulled out of your hands, and towards the dragon
As it reaches approximately Mach 2 right before impact, you take cover behind a cliff

The impact can only be compared to a small bomb. The entire cave shakes not unlike during an earthquake.
As you look up from you cover, you see the level 6 sword floating in place, just where the dragon used to be.
You walk up to the sword and inspect it closely.

On the blade you can see a faint inscription. You are pretty sure this wasn't here before:

HackTM{g3t_m0re_sl33p_and_dr1nk_m0re_water}
```

All steps to feed the game:

```
2
9e9
1
5
5
y
4
-1
5
y
4
1
 
 
 
3
 
```