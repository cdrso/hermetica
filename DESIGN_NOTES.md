## The data paralellization problem

The current implementation with rayon is much slower than the original sequential implementation.
One thing that would improve performance would probably be to increase the intermediate buffer size by orders of magnitude
The original implementation worked with bytemuck to avoid copies and clones to work with the bytes of data direcly instead of using methods like to_ne_bytes or from_ne_bytes
Need to find a way to reduce this as much as possible and get it as close as the sequential impl.
Need to understand how closures work with the caller environment

