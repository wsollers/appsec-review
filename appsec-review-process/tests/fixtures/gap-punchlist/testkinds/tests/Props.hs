import Test.QuickCheck

prop_rev xs = reverse (reverse xs) == (xs :: [Int])
