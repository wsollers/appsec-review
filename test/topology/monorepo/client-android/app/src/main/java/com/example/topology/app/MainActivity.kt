package com.example.topology.app

import com.example.topology.lib.Greeter

class MainActivity {
    fun title(): String = Greeter.greet("client")
}
