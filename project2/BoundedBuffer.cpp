/**	
 * Quinn Bigane
 *
 * COMP 375 Lab04
 *
 * 2/23/22
 *
 * Implementation of the BoundedBuffer class.
 * See the associated header file (BoundedBuffer.hpp) for the declaration of
 * this class.
 */
#include <cstdio>
#include <iostream>
#include <mutex>
#include <condition_variable>

#include "BoundedBuffer.hpp"

/**
 * Constructor that sets capacity to the given value. The buffer itself is
 * initialized to en empty queue.
 *
 * @param max_size The desired capacity for the buffer.
 */
BoundedBuffer::BoundedBuffer(int max_size) {
	capacity = max_size;
	count = 0;
	// buffer field implicitly has its default (no-arg) constructor called.
	// This means we have a new buffer with no items in it.
}

/**
 * Gets the first item from the buffer then removes it.
 */
int BoundedBuffer::getItem() {
	//lock aquire(lock)
	std::unique_lock<std::mutex> lock(shared_mutex);
	//while(count == 0) cond_wait(dataAvailable, lock)
	while(count == 0){
		dataAvailable.wait(lock);
	}
	//count--
	count--;
	int item = this->buffer.front(); // "this" refers to the calling object...
	buffer.pop(); // ... but like Java it is optional (no this in front of buffer on this line)
	//cond_signal(spaceAavailable. lock)
	spaceAvailable.notify_one();
	//lock release
	lock.unlock();
	return item;
}

/**
 * Adds a new item to the back of the buffer.
 *
 * @param new_item The item to put in the buffer.
 */
void BoundedBuffer::putItem(int new_item) {
	//Lock aquire(lock)
	std::unique_lock<std::mutex> lock(shared_mutex);
	//While(count == Size) cond_wait (SpaceAvailable, lock)
	while(count == capacity){
		spaceAvailable.wait(lock);
	}
	//count++
	count++;
	buffer.push(new_item);
	//cond_signal(dataAvailable, lock)
	dataAvailable.notify_one();
	//lock release(lock)
	lock.unlock();
}
