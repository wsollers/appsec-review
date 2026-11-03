using System;
using System.Linq;

namespace Demo
{
    public class Spans
    {
        private int limit = 3; // ANCHOR:none

        public Spans(int value) // BEGIN:ctor
        {
            limit = value; // ANCHOR:ctor
        } // END:ctor

        public int Count(string[] items) // BEGIN:Count
        {
            var kept = items.Where(item => {
                return item.Length > limit; // ANCHOR:Count
            }).ToArray();
            int Local(int x) { // BEGIN:Local
                return x + limit; // ANCHOR:Local
            } // END:Local
            return Local(kept.Length); // ANCHOR:Count
        } // END:Count
    }
}
